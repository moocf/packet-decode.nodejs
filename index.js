const readline = require('readline');




// HELPER FUNCTIONS
// ----------------

// Convert bytes to MAC address.
function bytesToMAC(bytes) {
  return bytes.map(b => b.toString(16).padStart(2, '0').toUpperCase()).join(':');
}


// Convert bytes to IPv4 address.
function bytesToIP(bytes) {
  return bytes.map(b => b.toString(10)).join('.');
}

// Convert hex string to byte array.
function hexToBytes(hex) {
  return hex.match(/.{1,2}/g).map(b => parseInt(b, 16));
}




// MAIN
// ----

// Q1. Parse Ethernet frame.
function parseEthernetFrame(bytes) {
  if (bytes.length < 14) throw new Error("Frame too short for valid Ethernet header");
  const destMAC = bytesToMAC(bytes.slice(0, 6));
  const srcMAC  = bytesToMAC(bytes.slice(6, 12));
  const type    = bytes[12] << 8 | bytes[13];
  const data    = bytes.slice(14);
  return {destMAC, srcMAC, type, data};
}


// Q2. Parse IPv4 packet.
function parseIPv4Packet(bytes) {
  if (bytes.length < 20) throw new Error("Packet too short for valid IPv4 header");
  const version = bytes[0] >> 4;
  const ihl     = bytes[0] & 0x0F;
  const dscp    = bytes[1] >> 2;
  const ecn     = bytes[1] & 0x03;
  const totalLength    = (bytes[2] << 8) | bytes[3];
  const identification = (bytes[4] << 8) | bytes[5];
  const flags = bytes[6] >> 5;
  const fragmentOffset = ((bytes[6] & 0x1F) << 8) | bytes[7];
  const ttl   = bytes[8];
  const protocol = bytes[9];
  const checksum = (bytes[10] << 8) | bytes[11];
  // Source and Destination IPs
  const srcIP = bytesToIP(bytes.slice(12, 16));
  const dstIP = bytesToIP(bytes.slice(16, 20));
  // Data starts after the IPv4 header
  const data  = bytes.slice(ihl * 4);  // Number of 32-bit words in header * 4 bytes
  return {
    version, ihl, dscp, ecn, totalLength, identification,
    flags, fragmentOffset, ttl, protocol, checksum, srcIP, dstIP, data
  };
}


// Q3. Parse TCP segment.
function parseTCPSegment(bytes) {
  if (bytes.length < 20) throw new Error("Segment too short for valid TCP header");
  const srcPort = (bytes[0] << 8) | bytes[1];
  const dstPort = (bytes[2] << 8) | bytes[3];
  const seqNum  = (bytes[4] << 24) | (bytes[5] << 16) | (bytes[6] << 8) | bytes[7];
  const ackNum  = (bytes[8] << 24) | (bytes[9] << 16) | (bytes[10] << 8) | bytes[11];
  const dataOffset = bytes[12] >> 4;
  const flags = bytes[13] & 0x3F; // last 6 bits are flags
  const urg   = (flags & 0x20) !== 0;
  const ack   = (flags & 0x10) !== 0;
  const psh   = (flags & 0x08) !== 0;
  const rst   = (flags & 0x04) !== 0;
  const syn   = (flags & 0x02) !== 0;
  const fin   = (flags & 0x01) !== 0;
  const windowSize    = (bytes[14] << 8) | bytes[15];
  const tcpChecksum   = (bytes[16] << 8) | bytes[17];
  const urgentPointer = (bytes[18] << 8) | bytes[19];
  const data = bytes.slice(dataOffset * 4);  // Data offset in 32-bit words, so multiply by 4
  return {
    srcPort, dstPort, seqNum, ackNum, dataOffset,
    flags: { urg, ack, psh, rst, syn, fin },
    windowSize, tcpChecksum, urgentPointer, data
  };
}



// Main function to decode Ethernet frames and IPv4 packets.
async function main() {
  const rl = readline.promises.createInterface({
    input:  process.stdin,
    output: process.stdout
  });

  const hex   = (await rl.question("Enter Ethernet frame in hex: ")).replace(/\s+/g, '').toLowerCase();
  const bytes = hexToBytes(hex);

  if (bytes.length < 14) {
    console.log("Frame too short for valid Ethernet header");
    rl.close();
    return;
  }

  // Q1. Parse Ethernet Header.
  const eth = parseEthernetFrame(bytes);
  console.log("\n=== Ethernet Frame ===");
  console.log(`Destination MAC: ${eth.destMAC}`);
  console.log(`Source MAC:      ${eth.srcMAC}`);
  console.log(`Type:            0x${eth.type.toString(16).padStart(4, '0')}`);
  // console.log(`Data:\n${eth.data}\n`);

  // IPv4 Decoding
  if (eth.type !== 0x0800) {
    console.log("Non-IPv4 Ethernet frame! Decoding not implemented.");
    rl.close();
    return;
  }
  const ip = parseIPv4Packet(eth.data);
  console.log("\n=== IPv4 Packet ===");
  console.log(`Version:              ${ip.version}`);
  console.log(`Header Length:        ${ip.ihl * 4} bytes`);
  console.log(`DSCP:                 ${ip.dscp}`);
  console.log(`ECN:                  ${ip.ecn}`);
  console.log(`Total Length:         ${ip.totalLength} bytes`);
  console.log(`Identification:       0x${ip.identification.toString(16).padStart(4, '0')}`);
  console.log(`Flags:                0b${ip.flags.toString(2).padStart(3, '0')}`);
  console.log(`Fragment Offset:      ${ip.fragmentOffset}`);
  console.log(`Time To Live (TTL):   ${ip.ttl}`);
  console.log(`Protocol:             ${ip.protocol}`);
  console.log(`Header Checksum:      0x${ip.checksum.toString(16).padStart(4, '0')}`);
  console.log(`Source IP:            ${ip.srcIP}`);
  console.log(`Destination IP:       ${ip.dstIP}`);
  // console.log(`Data:\n${ip.data}\n`);

  // TCP Parsing
  if (ip.protocol !== 6) {
    console.log("\nNon-TCP Protocol detected. Decoding not implemented for this protocol.");
    rl.close();
    return;
  }
  const tcp = parseTCPSegment(ip.data);
  console.log("\n=== TCP Segment ===");
  console.log(`Source Port:          ${tcp.srcPort}`);
  console.log(`Destination Port:     ${tcp.dstPort}`);
  console.log(`Sequence Number:      ${tcp.seqNum}`);
  console.log(`Acknowledgment Number:${tcp.ackNum}`);
  console.log(`Data Offset:          ${tcp.dataOffset} bytes`);
  console.log(`Flags:                URG=${tcp.flags.urg}, ACK=${tcp.flags.ack}, PSH=${tcp.flags.psh}, RST=${tcp.flags.rst}, SYN=${tcp.flags.syn}, FIN=${tcp.flags.fin}`);
  console.log(`Window Size:          ${tcp.windowSize}`);
  console.log(`Checksum:             0x${tcp.tcpChecksum.toString(16).padStart(4, '0')}`);
  console.log(`Urgent Pointer:       ${tcp.urgentPointer}`);
  // console.log(`Data:\n${tcp.data}\n`);
  console.log(`Text data:\n${Buffer.from(tcp.data, 'hex').toString('utf8')}\n`);

  rl.close();
}

main();
