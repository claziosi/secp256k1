use actix_cors::Cors;
use actix_web::{web, App, HttpResponse, HttpServer, Responder, http};
use openssl::bn::BigNumContext;
use openssl::hash::MessageDigest;
use serde::Deserialize;
use openssl::ec::{EcGroup, EcKey, EcPoint};
use openssl::nid::Nid;
use openssl::pkey::PKey;
use openssl::sign::Verifier;

#[derive(Deserialize)]
pub struct SignedMessage {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}

// Handler for validating signatures
async fn validate_signature(signed_message: web::Json<SignedMessage>) -> impl Responder {
    
    // Convert hexadecimal strings to byte slices
    let public_key_bytes = hex::decode(&signed_message.public_key).unwrap();
    let signature_bytes = hex::decode(&signed_message.signature).unwrap();

    println!("--------------------");
    println!("Public key: {}", hex::encode(&public_key_bytes[..]));
    println!("Message: {}", signed_message.message);
    println!("Signature: {}", hex::encode(&signature_bytes[..]));
    print!("--------------------");

    // Initialize a BigNumContext
    let mut ctx = BigNumContext::new().unwrap();

    // Create an EC key directly from the public key bytes
    let group = EcGroup::from_curve_name(Nid::SECP256K1).unwrap();
    let ec_point = EcPoint::from_bytes(&group, &public_key_bytes, &mut ctx).unwrap();
    let ec_key = EcKey::from_public_key(&group, &ec_point).unwrap();
    let pkey = PKey::from_ec_key(ec_key).unwrap();

    // Create a verifier with the EC public key
    let mut verifier = Verifier::new(MessageDigest::sha256(), &pkey).unwrap();

    // Convert the message to a byte slice
    let msg = hex::decode(&signed_message.message).unwrap();

    // Verify the signature
    verifier.update(&msg).unwrap();

    match verifier.verify(&signature_bytes) {
        Ok(_) => HttpResponse::Ok().body("true"),
        Err(_) => HttpResponse::BadRequest().body("Invalid signature"),
    } 
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
            .route("/validate_signature", web::post().to(validate_signature))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}