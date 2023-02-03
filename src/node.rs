use ockam::authenticated_storage::{AuthenticatedStorage, InMemoryStorage};
use ockam::identity::credential::Credential;
use ockam::identity::{Identity, PublicIdentity, TrustEveryonePolicy};
use ockam::{
    errcode::Kind, errcode::Origin, route, vault::Vault, Address, Context, Message, Result,
    TcpTransport, TCP,
};

use async_trait::async_trait;
use core::time::Duration;
use std::collections::HashMap;
use std::fmt::Debug;

use crate::credential_manager::{CredentialRequest, CredentialResponseDecoded, RequestCredential};

#[async_trait]
pub trait EndPoint {
    async fn start<S: AuthenticatedStorage>(&self, ctx: &Context, storage: S) -> Result<()>;
    fn endpoint(&self) -> String;
}

pub struct Node {
    pub connections: HashMap<String, Address>,
    pub identity: Identity<Vault>,
    vault: Vault,
    storage: InMemoryStorage,
    authorities: Vec<PublicIdentity>,
}

impl Node {
    pub async fn new(ctx: &mut Context, storage: InMemoryStorage) -> Self {
        let vault = Vault::create();
        let identity = Identity::create(ctx, &vault).await.unwrap();

        Node {
            connections: HashMap::new(),
            identity,
            vault,
            storage,
            authorities: vec![],
        }
    }

    pub async fn add_authority(&mut self, identity: PublicIdentity) -> Result<()> {
        self.authorities.push(identity);
        Ok(())
    }

    pub async fn present_credential(&mut self, name: &str) -> Result<()> {
        if let Some(address) = self.connections.get(name) {
            self.identity
                .present_credential_mutual(
                    route![address.clone(), "credential_exchange"],
                    &self.authorities,
                    &self.storage,
                )
                .await?;
        }
        Ok(())
    }

    pub async fn start_credential_exchange(&mut self) -> Result<()> {
        self.identity
            .start_credentials_exchange_worker(
                self.authorities.clone(),
                "credential_exchange",
                true,
                self.storage.clone(),
            )
            .await?;

        Ok(())
    }

    pub async fn set_identity(&mut self, cred: CredentialResponseDecoded<'static>) -> Result<()> {
        self.identity
            .verify_self_credential(&cred.credential, vec![&cred.authority])
            .await?;
        self.identity.set_credential(Some(cred.credential)).await;
        self.add_authority(cred.authority.clone()).await?;

        Ok(())
    }

    pub async fn request_credential<'a, 'b>(
        &self,
        ctx: &mut Context,
        from: &str,
    ) -> Result<CredentialResponseDecoded<'b>> {
        let id = self.identity.identifier();
        let request = RequestCredential::Request(CredentialRequest {
            pass: "1234".to_string(),
            identity: id.to_string(),
        });

        if let Some(address) = self.connections.get(from) {
            ctx.send(route![address.to_owned(), "identity_manager"], request)
                .await?;

            let result = ctx.receive::<RequestCredential>().await?;

            if let RequestCredential::Response(result) = (*result).clone() {
                let credential: Credential = minicbor::decode(result.credential.as_slice())?;
                let public_id = PublicIdentity::import(&result.authority, &self.vault).await?;
                Ok(CredentialResponseDecoded {
                    credential: credential.to_owned(),
                    authority: public_id,
                })
            } else {
                Err(ockam::Error::new_without_cause(
                    Origin::Application,
                    Kind::Invalid,
                ))
            }
        } else {
            Err(ockam::Error::new_without_cause(
                Origin::Application,
                Kind::Invalid,
            ))
        }
    }

    pub async fn listen(&mut self, tcp: &TcpTransport, port: &str) -> Result<()> {
        // Initialize the TCP Transport.
        tcp.listen(format!("0.0.0.0:{port}")).await?;

        self.identity
            .create_secure_channel_listener("untrusted", TrustEveryonePolicy, &self.storage)
            .await?;

        Ok(())
    }

    pub async fn connect(&mut self, name: &str, addr: &str) -> Result<()> {
        let route = route![(TCP, addr), "untrusted"];
        let node_address = self
            .identity
            .create_secure_channel_extended(
                route,
                TrustEveryonePolicy,
                &self.storage,
                Duration::from_secs(2),
            )
            .await?;

        self.connections.insert(name.to_string(), node_address);
        Ok(())
    }

    pub async fn send<M: Message + Debug>(
        &mut self,
        ctx: &Context,
        name: &str,
        endpoint: &str,
        message: M,
    ) -> Result<M> {
        if let Some(address) = self.connections.get(name) {
            let resp: M = ctx
                .send_and_receive(route![address.to_owned(), endpoint], message)
                .await?;

            Ok(resp)
        } else {
            Err(ockam::Error::new_without_cause(
                Origin::Application,
                Kind::Misuse,
            ))
        }
    }
}
