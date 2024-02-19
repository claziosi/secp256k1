use actix_web::{get, web::ServiceConfig};
use serde::{Deserialize, Serialize};

use crate::AuthToken;

pub(super) fn configure() -> impl FnOnce(&mut ServiceConfig) {
    |config: &mut ServiceConfig| {
        config 
            .service(auth);
    }
}


#[derive(Serialize, Deserialize, Clone)]
pub struct SignedMessage {
    pub message: String,
    pub signature: String,
    pub public_key: String,
}


/// Authentication endpoint
///
/// Authenticate user
///
#[get("/auth", wrap = "AuthToken")]
// Handler for validating signatures
pub(super) async fn auth() -> String {
    //Return the string "Authenticated"... 
    // But to execute the code below, we must pass the AuthToken middleware
    // The AuthToken middleware will validate the token and only then execute the code below
    "Authenticated".to_string()
}
