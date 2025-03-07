use crate::models::Claims;
use jsonwebtoken::{decode, errors::Error as JwtError, Algorithm, DecodingKey, Validation};

pub fn decode_jwt(token: &str, secret: &str) -> Result<String, JwtError> {
    let decoding_key = DecodingKey::from_secret(secret.as_bytes());
    let validation = Validation::new(Algorithm::HS256);

    decode::<Claims>(token, &decoding_key, &validation)
        .map(|token_data| token_data.claims.id)
        .map_err(|e| {
            tracing::error!(error = %e, "JWT decode failed");
            e
        })
}
