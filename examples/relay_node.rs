use async_trait::async_trait;
use ockam::authenticated_storage::{AuthenticatedStorage, InMemoryStorage};
use ockam::identity::credential::access_control::CredentialAccessControl;
use ockam::{
    errcode::Kind, errcode::Origin, Context, Result, Routed, TcpTransport, Worker, WorkerBuilder,
};
use serde::Deserialize;
use serva::node::{EndPoint, Node};
use std::env;
use std::fs;
use std::sync::Arc;

#[derive(Clone)]
struct InletManager {
    tcp: Arc<TcpTransport>,
}

const ANACAPA_PORT: i32 = 10000;
const OUTLET_NAME: &str = "outlet";
const BASE_PORT: u16 = 9000;

impl InletManager {
    pub fn new(tcp: Arc<TcpTransport>) -> Self {
        Self { tcp}
    }
}

// Define an Echoer worker that prints any message it receives and
// echoes it back on its return route.
#[ockam::worker]
impl Worker for InletManager {
    type Message = String;
    type Context = Context;

    async fn handle_message(
        &mut self,
        ctx: &mut self::Context,
        msg: Routed<Self::Message>,
    ) -> ockam::Result<()> {
        let return_route = msg.return_route();
        let msg = msg.body();

        let params: Vec<&str> = msg.split(' ').collect();

        let port = BASE_PORT
            + params.first().unwrap().parse::<u16>().map_err(|_| {
                ockam::Error::new(
                    Origin::Application,
                    Kind::Invalid,
                    "InletManager: Invalid argument",
                )
            })?;

        let node_name = params.last().unwrap();

        // the incoming traffic from the inlet will be redirected
        // to this address
        let inlet_dst = {
            let mut route = return_route.clone();
            route.modify().pop_back().append(*node_name);
            route
        };

        let addr = format!("0.0.0.0:{}", port);

        // create the inlet
        self.tcp.create_inlet(addr, inlet_dst).await?;

        println!(
            "Created new tunnel from port {} to node {}",
            port, node_name
        );

        // answer with the port that we are listening to
        ctx.send(return_route, port.to_string()).await?;

        Ok(())
    }
}

#[async_trait]
impl EndPoint for InletManager {
    fn endpoint(&self) -> String {
        String::from("echo")
    }

    async fn start<S: AuthenticatedStorage>(&self, ctx: &Context, storage: S) -> Result<()> {
        let required_attributes = vec![("is_sonos".to_string(), b"true".to_vec())];
        let access_control = CredentialAccessControl::new(&required_attributes, storage);

        WorkerBuilder::with_access_control(access_control, &self.endpoint(), self.to_owned())
            .start(ctx)
            .await?;

        Ok(())
    }
}

#[derive(Deserialize)]
struct NodeConfig {
    credential_manager: String,
    listen_port: String,
    nodes: Vec<String>,
}

#[ockam::node]
async fn main(ctx: &mut Context) -> Result<()> {
    let args: Vec<String> = env::args().collect();

    let config_name = args[1].as_str();
    let config_file = fs::read_to_string(config_name).expect("Unable to read config {config_name}");
    let config: NodeConfig = toml::from_str(&config_file).unwrap();
    let storage = InMemoryStorage::new();

    let interfaces = pnet_datalink::interfaces();
    let br0 = interfaces
        .iter()
        .filter(|i| i.name == "br0")
        .next()
        .and_then(|i| i.ips.first().and_then(|ip| Some(ip.ip())))
        .unwrap();

    let port_map = br0
        .to_string()
        .split('.')
        .last()
        .unwrap()
        .parse::<u16>()
        .unwrap();

    println!(
        "Config
    credential-manager:{}
    listen-port:{}
    nodes:{:?}
    ",
        config.credential_manager, config.listen_port, config.nodes
    );


    let tcp = Arc::new(TcpTransport::create(&ctx).await.unwrap());

    let mut me = Node::new(&mut ctx, storage.clone()).await;

    //get credential
    me.connect("key_manager", &config.credential_manager)
        .await?;
    let cred = me.request_credential(&mut ctx, "key_manager").await?;
    if me.set_identity(cred).await.is_err() {
        println!("Invalid credential received");
    }
    me.start_credential_exchange().await?;
    me.listen(&tcp, &config.listen_port).await?;

    // create outlet for sending messages to the given port
    tcp.create_outlet(OUTLET_NAME, format!("127.0.0.1:{}", ANACAPA_PORT))
        .await?;

    // start inlet manager
    let inlet_manager = InletManager::new(tcp);
    inlet_manager.start(&ctx, storage.to_owned()).await?;

    loop {
        if me.connect("sibling1", &config.nodes[0]).await.is_ok() {
            if me.present_credential("sibling1").await.is_err() {
                println!("error presenting creds");
            } else {
                println!(
                    "Sent: {br0} Received: {}",
                    me.send(
                        &ctx,
                        "sibling1",
                        &inlet_manager.endpoint(),
                        format!("{} {}", port_map, OUTLET_NAME),
                    )
                    .await?
                );
            }
            break;
        } else {
            println!("no sibling1 retry");
            std::thread::sleep(std::time::Duration::from_secs(2));
        }
    }
    println!("connected");

    Ok(())
}
