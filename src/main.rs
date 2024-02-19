use std::future::{self, Ready};

use actix_cors::Cors;
use actix_web::dev::{Service, ServiceRequest, ServiceResponse, Transform};
use actix_web::{http, App, HttpResponse, HttpServer};
use base64::engine::general_purpose;
use base64::Engine;
use futures::future::LocalBoxFuture;
use openssl::bn::BigNumContext;
use serde::{Deserialize, Serialize};
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;

mod auth;

#[derive(Deserialize)]
pub struct SignedMessage {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}


#[actix_web::main]
async fn main() -> std::io::Result<()> {
    HttpServer::new(|| {
        let cors = Cors::default()
            .allowed_origin("http://localhost:3000") // Allow only http://localhost as origin
            .allowed_methods(vec!["GET", "POST"]) // Specify allowed methods
            .allowed_headers(vec![http::header::AUTHORIZATION, http::header::ACCEPT])
            .allowed_header(http::header::CONTENT_TYPE)
            .max_age(3600); // Set max age for preflight cache
        
        App::new()
            .wrap(cors) // Apply CORS middleware to all routes
            .wrap(Cors::permissive())   // Apply CORS middleware to all routes but comment this line for PRODUCTION !!
            // Apply the RequireBearerToken middleware to all routes
            .configure(auth::configure())
            
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}


/// Error response for Object endpoints
#[derive(Serialize, Deserialize, Clone)]
pub enum ErrorResponse {
    /// When Object is not found by search term.
    NotFound(String),
    /// When there is a conflict storing a new object.
    Conflict(String),
    /// When object endpoint was called without correct credentials
    Unauthorized(String),
    /// When there is an internal server error
    InternalServerError(String),
}


/// 
/// Middleware to require a Bearer token
/// 
/// This middleware will check if the request has a valid Bearer token
/// If the token is valid, the request will be passed to the next middleware
/// If the token is invalid, the request will be rejected
/// 
struct AuthToken;

impl<S> Transform<S, ServiceRequest> for AuthToken
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Transform = AuthMiddleware<S>;
    type InitError = ();
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ready(Ok(AuthMiddleware {
            service,
        }))
    }
}

struct AuthMiddleware<S> {
    service: S,
}

impl<S> Service<ServiceRequest> for AuthMiddleware<S>
where
    S: Service<
        ServiceRequest,
        Response = ServiceResponse<actix_web::body::BoxBody>,
        Error = actix_web::Error,
    >,
    S::Future: 'static,
{
    type Response = ServiceResponse<actix_web::body::BoxBody>;
    type Error = actix_web::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, actix_web::Error>>;

    fn poll_ready(
        &self,
        ctx: &mut core::task::Context<'_>,
    ) -> std::task::Poll<Result<(), Self::Error>> {
        self.service.poll_ready(ctx)
    }

    fn call(&self, req: ServiceRequest) -> Self::Future {

        let response = |req: ServiceRequest, response: HttpResponse| -> Self::Future {
            Box::pin(async { Ok(req.into_response(response)) })
        };

        println!("Request: {:?}", req);
        // Check if the signature is valid 
        // Get the token from the request Authorization base64 header and decode it
        // manage if the token is empty or invalid
        let authorization_header = match req.headers().get("Authorization") {
            Some(header) => header,
            None => {
                return response(
                    req,
                    HttpResponse::Unauthorized()
                        .json(ErrorResponse::Unauthorized(String::from("Missing Token"))),
                );
            }
        };
        
        //replace "Bearer " with "" to get the token
        let authorization_header = authorization_header.to_str().unwrap().replace("Bearer ", "");

        // Decode the base64token to a string
        let base64_token = authorization_header;
        let token_bytes =  match general_purpose::STANDARD.decode(base64_token) {
            Ok(token) => token,
            Err(_) => {
                return response(
                    req,
                    HttpResponse::Unauthorized()
                        .json(ErrorResponse::Unauthorized(String::from("Malformed/Invalid Token"))),
                );
            }
        };
        
        let token = String::from_utf8(token_bytes).unwrap();

        let public_key = token.split(":").collect::<Vec<&str>>()[0];
        let signature = token.split(":").collect::<Vec<&str>>()[1];
        let message = token.split(":").collect::<Vec<&str>>()[2];

        // Nonce to prevent replay attacks (to be sent to the client on a regular basis)
        // Change the nonce will prevent the reuse of the same signature twice
        let nonce = "30450221009137c8489f844822843868d77f93c288ea64427005".as_bytes().to_vec();

        // Convert hexadecimal strings to byte slices
        let public_key_bytes = hex::decode(&public_key).unwrap();
        let signature_bytes = hex::decode(&signature).unwrap();


        // Initialize a BigNumContext
        let mut ctx = BigNumContext::new().unwrap();

        // Create an EC key directly from the public key bytes
        let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
        let ec_point = EcPoint::from_bytes(&group, &public_key_bytes, &mut ctx).unwrap();
        let ec_key = EcKey::from_public_key(&group, &ec_point).unwrap();
        let pkey = PKey::from_ec_key(ec_key).unwrap();

        // Initialize a verifier
        let mut verifier = Verifier::new_without_digest(&pkey).unwrap();

        // Convert the message to a byte slice
        let mut msg = message.bytes().collect::<Vec<u8>>();

        // Concatenate msg and once
        msg.extend_from_slice(&nonce);

        let result = verifier.verify_oneshot(&signature_bytes, &msg).unwrap();

        if result {
            // If the signature is valid, call the next middleware
            let future = self.service.call(req);

            Box::pin(async move {
                let response = future.await?;
                Ok(response)
            })
        } else {
            // If the signature is invalid, return an error
            return response(
                req,
                HttpResponse::Unauthorized()
                    .json(ErrorResponse::Unauthorized(String::from("Invalid Token"))),
            );
        }
        

    }
}