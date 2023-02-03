use ockam::authenticated_storage::InMemoryStorage;
use ockam::{Context, Result, TcpTransport};

#[ockam::node]
async fn main(ctx: &mut Context) -> Result<()> {
    // Initialize the TCP Transport.
    let tcp = TcpTransport::create(&ctx).await?;
    let storage = InMemoryStorage::new();

    let mut server = serva::node::Node::new(&mut ctx, storage.clone()).await;
    server.listen(&tcp, "4001").await?;
    server.start_credential_exchange().await?;

    let manager = serva::credential_manager::CredentialManager::new(&mut ctx).await?;
    ctx.start_worker("identity_manager", manager).await?;

    Ok(())
}
