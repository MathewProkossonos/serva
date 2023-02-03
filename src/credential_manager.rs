use ockam::authenticated_storage::InMemoryStorage;
use ockam::identity::{credential::Credential, Identity, IdentityIdentifier, PublicIdentity};
use ockam::{vault::Vault, Context, Message, Result, Routed, Worker};

use serde::{Deserialize, Serialize};

use std::str::FromStr;

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Message)]
pub struct CredentialRequest {
    pub pass: String,
    pub identity: String,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Message)]
pub struct CredentialResponse {
    pub credential: Vec<u8>,
    pub authority: Vec<u8>,
}

pub struct CredentialResponseDecoded<'a> {
    pub credential: Credential<'a>,
    pub authority: PublicIdentity,
}

#[derive(Serialize, Deserialize, Debug, Clone, Hash, Ord, PartialOrd, Eq, PartialEq, Message)]
pub enum RequestCredential {
    Request(CredentialRequest),
    Response(CredentialResponse),
    Denied,
}

pub struct CredentialManager {
    identity: Identity<Vault>,
}

impl CredentialManager {
    pub async fn new(ctx: &mut Context) -> Result<Self> {
        let vault = Vault::create();
        let identity = Identity::create(ctx, &vault).await?;

        Ok(Self { identity })
    }
}

// Define an Echoer worker that prints any message it receives and
// echoes it back on its return route.
#[ockam::worker]
impl Worker for CredentialManager {
    type Context = Context;
    type Message = RequestCredential;

    async fn handle_message(
        &mut self,
        ctx: &mut Context,
        msg: Routed<RequestCredential>,
    ) -> ockam::Result<()> {
        let body = msg.as_body();
        match body {
            RequestCredential::Request(CredentialRequest { pass, identity }) if pass == "1234" => {
                let id = IdentityIdentifier::from_str(&identity)?;
                let builder = Credential::builder(id.clone());
                let attributes = builder.with_attribute("is_sonos", b"true");
                let credential = self.identity.issue_credential(attributes).await?;
                let credential_encoded = minicbor::to_vec(&credential)?;
                let public_id = self.identity.to_public().await?;

                let result = CredentialResponse {
                    credential: credential_encoded,
                    authority: public_id.export()?,
                };
                ctx.send(msg.return_route(), RequestCredential::Response(result))
                    .await?
            }
            _ => {
                ctx.send(msg.return_route(), RequestCredential::Denied)
                    .await?;
            }
        }

        Ok(())
    }
}
