#!/usr/bin/env python3

from scapy.all import *
from scapy.contrib.pfcp import *
from scapy.layers.inet import IP  # This is to calm down PyCharm's linter
from scapy.contrib.gtp import IE_Cause as GTP_IE_Cause
from scapy.contrib.gtp import GTP_U_Header
import time
import pytest
import os

# Configuration for running in local environment
# Default configuration values
DEFAULT_TARGET_IP = "172.19.0.2"
DEFAULT_TARGET_PORT = 8805
DEFAULT_SOURCE_PORT = 33100
DEFAULT_INTERFACE = "br-ccb8b956d6d8"

# Configuration for running in container
# DEFAULT_TARGET_IP = "127.0.0.1"
# DEFAULT_TARGET_PORT = 8805
# DEFAULT_SOURCE_PORT = 33100
# DEFAULT_INTERFACE = "lo"

# Allow overriding via environment variables
TARGET_IP = os.getenv("EUPF_TARGET_IP", DEFAULT_TARGET_IP)
TARGET_PORT = int(os.getenv("EUPF_TARGET_PORT", DEFAULT_TARGET_PORT))
SOURCE_PORT = int(os.getenv("EUPF_SOURCE_PORT", DEFAULT_SOURCE_PORT))
INTERFACE = os.getenv("EUPF_INTERFACE", DEFAULT_INTERFACE)

@pytest.fixture(scope="session")
def target():
    return IP(dst=TARGET_IP) / UDP(sport=SOURCE_PORT, dport=TARGET_PORT)

association_request = PFCP(version=1, S=0, seq=1) / \
                      PFCPAssociationSetupRequest(IE_list=[
                          IE_RecoveryTimeStamp(timestamp=3785653512),
                          IE_NodeId(id_type="FQDN", id="BIG-IMPORTANT-CP")
                      ])

session_establish = PFCP(version=1, S=1, seq=2, seid=0, spare_oct=0) / \
                    PFCPSessionEstablishmentRequest(IE_list=[
                        IE_CreateFAR(IE_list=[
                            IE_ApplyAction(FORW=1),
                            IE_FAR_Id(id=1),
                            IE_ForwardingParameters(IE_list=[
                                IE_DestinationInterface(interface="Access"),
                                IE_NetworkInstance(instance="access"),
                                IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=0x01000000, ipv4="10.23.118.70"),
                            ])
                        ]),
                        IE_CreateFAR(IE_list=[
                            IE_ApplyAction(DROP=1),
                            IE_FAR_Id(id=2)
                        ]),
                        IE_CreatePDR(IE_list=[
                            IE_FAR_Id(id=1),
                            IE_OuterHeaderRemoval(header="GTP-U/UDP/IPv4"),
                            IE_PDI(IE_list=[
                                IE_FTEID(V4=1, TEID=0x104c9033, ipv4="172.19.0.1"),
                                IE_NetworkInstance(instance="access"),
                                IE_SourceInterface(interface="Access"),
                            ]),
                            IE_PDR_Id(id=1),
                            IE_Precedence(precedence=100)
                        ]),
                        IE_FSEID(v4=1, seid=0xffde7230bf97810a, ipv4="172.19.0.1"),
                        IE_NodeId(id_type="FQDN", id="BIG-IMPORTANT-CP")
                    ])

session_modification = PFCP(version=1, S=1, seq=2, seid=2, spare_oct=0) / \
                       PFCPSessionModificationRequest(IE_list=[
                           IE_UpdateFAR(IE_list=[
                               IE_ApplyAction(FORW=1),
                               IE_FAR_Id(id=2),
                               IE_UpdateForwardingParameters(IE_list=[
                                   IE_DestinationInterface(interface="Access"),
                                   IE_NetworkInstance(instance="access"),
                                   IE_OuterHeaderCreation(GTPUUDPIPV4=1, TEID=0x01000001, ipv4="10.23.118.69"),
                               ])
                           ]),
                           IE_RemoveFAR(IE_list=[
                               IE_ApplyAction(DROP=1),
                               IE_FAR_Id(id=1)
                           ]),
                           IE_UpdatePDR(IE_list=[
                               IE_FAR_Id(id=1),
                               IE_OuterHeaderRemoval(header="GTP-U/UDP/IPv4"),
                               IE_PDI(IE_list=[
                                   IE_FTEID(V4=1, TEID=0x104c9033, ipv4="172.18.1.2"),
                                   IE_NetworkInstance(instance="access"),
                                   IE_SourceInterface(interface="Access"),
                               ]),
                               IE_PDR_Id(id=1),
                               IE_Precedence(precedence=100)
                           ]),
                           IE_FSEID(v4=1, seid=0xffde7230bf97810a, ipv4="172.18.1.1"),
                           IE_NodeId(id_type="FQDN", id="BIG-IMPORTANT-CP")
                       ])

session_delete = PFCP(version=1, S=1, seq=3, seid=2, spare_oct=0) / \
                 PFCPSessionDeletionRequest(IE_list=[
                     IE_FSEID(v4=1, seid=0xffde7230bf97810a, ipv4="172.18.1.1"),
                     IE_NodeId(id_type="FQDN", id="BIG-IMPORTANT-CP")
                 ])

heartbeat_response = PFCP(version=1, S=0, seq=1, seid=2, spare_oct=0) / \
                     PFCPHeartbeatResponse(IE_list=[
                         IE_RecoveryTimeStamp(timestamp=int(time.time()))
                     ])

ue_ip_address = IE_UE_IP_Address(spare=2, SD=0, V4=0)
session_establish_ueip = PFCP(version=1, S=1, seq=2, seid=0, spare_oct=0) / \
                         PFCPSessionEstablishmentRequest(IE_list=[
                             IE_CreatePDR(IE_list=[
                                 IE_FAR_Id(id=1),
                                 IE_OuterHeaderRemoval(header="GTP-U/UDP/IPv4"),
                                 IE_PDI(IE_list=[
                                     ue_ip_address,
                                     # IE_NetworkInstance(instance="access"),
                                     IE_SourceInterface(interface="Access"),
                                 ]),
                                 IE_PDR_Id(id=1),
                                 IE_Precedence(precedence=100)
                             ]),
                             IE_FSEID(v4=1, seid=0xffde7230bf97810a, ipv4="172.18.1.1"),
                             IE_NodeId(id_type="FQDN", id="BIG-IMPORTANT-CP")
                         ])

# https://stackoverflow.com/questions/41166420/sending-a-packet-over-physical-loopback-in-scapy
conf.L3socket = L3RawSocket

# target = IP(dst="127.0.0.1") / UDP(sport=33100, dport=8805)
# target = IP(dst="172.21.0.2") / UDP(sport=33100, dport=8805)

# TODO: Add state checks via eUPF web API

def test_create_association(target):
    ans = sr1(target / association_request, iface=INTERFACE)
    assert ans.haslayer(PFCPAssociationSetupResponse)
    assert ans[PFCPAssociationSetupResponse][IE_Cause].cause == 1


def test_create_session(target):
    ans = sr1(target / session_establish, iface=INTERFACE)
    assert ans.haslayer(PFCPSessionEstablishmentResponse)
    assert ans[PFCPSessionEstablishmentResponse][IE_Cause].cause == 1

def test_gtp_traffic(target):
    # 2. Create GTP packet matching the PFCP session
    payload = IP(src="192.168.1.100", dst="8.8.8.8")/ICMP()
    gtp_packet = (
        IP(src="172.19.0.1", dst=TARGET_IP) /
        UDP(sport=2152, dport=2152) /
        GTP_U_Header(teid=0x104c9033, gtp_type=255) /
        payload
    )

    # 3. Send GTP packet and capture response
    # Using AsyncSniffer to capture the modified packet
    sniffer = AsyncSniffer(
        iface=INTERFACE,
        lfilter=lambda x: x.haslayer(GTP_U_Header)
    )
    sniffer.start()

    time.sleep(.01)
    # Send the original GTP packet
    send(gtp_packet, iface=INTERFACE)

    # Wait for capture
    time.sleep(.01)
    sniffer.stop()

    # 4. Verify captured packets
    captured = sniffer.results
    print('captured: ', captured, 'len: ', len(captured))
    assert len(captured) > 0, "No modified GTP packets captured"

    # The first packet is the original packet, the second is the modified packet
    modified_packet = captured[1]

    # Verify the packet was modified according to FAR
    assert modified_packet[IP].dst == "10.23.118.70"
    assert modified_packet[GTP_U_Header].teid == 0x01000000

    # Verify the inner packet remained unchanged
    # Handling encapsulated IP-in-IP packets
    if IP in modified_packet[IP].payload:
        inner_ip_src = modified_packet[IP].payload[IP].src
        inner_ip_dst = modified_packet[IP].payload[IP].dst
        assert inner_ip_src == "192.168.1.100"
        assert inner_ip_dst == "8.8.8.8"

def test_modify_session(target):
    ans = sr1(target / session_modification, iface=INTERFACE)
    assert ans.haslayer(PFCPSessionModificationResponse)
    assert ans[PFCPSessionModificationResponse][IE_Cause].cause == 1


def test_delete_session(target):
    ans = sr1(target / session_delete, iface=INTERFACE)
    assert ans.haslayer(PFCPSessionDeletionResponse)
    assert ans[PFCPSessionDeletionResponse][IE_Cause].cause == 1


def test_send_heartbeat(target):
    # This is imaginary HearBeatResponse, this should not crash eUPF
    send(target / heartbeat_response, iface=INTERFACE)


def test_create_session_ueip(target):
    ans = sr1(target / session_establish_ueip, iface=INTERFACE)
    assert ans.haslayer(PFCPSessionEstablishmentResponse)
    assert ans[PFCPSessionEstablishmentResponse][IE_CreatedPDR][IE_UE_IP_Address].ipv4 == "10.60.0.1"
