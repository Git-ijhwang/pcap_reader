#![allow(dead_code)]
// [ 3GPP TS 29.274 V10.5.0 (2011-12) ]
pub const GTP_VERSION: u8 = 	                    	            0x02;
pub const GTPV2_P_FLAG: u8 =                    		            0x10;
pub const GTPV2_T_FLAG: u8 = 	     	                            0x08;
pub const GTPV2C_MINIMUM_HEADER_SIZE: u8 = 		                8;
const GTPV2C_EPC_SPECIFIC_HEADER_SIZE: u8 = 		            12;
 
// GTPv2-C Message Type Values
pub const GTPV2C_ECHO_REQ: u8 = 		                            1;
pub const GTPV2C_ECHO_RSP: u8 = 		                            2;
pub const GTPV2C_VERSION_NOT_SUPPORTED_IND: u8 = 		            3;

// SGSN/MME/ePDG to PGW (S4/S11, S5/S8, S2b)
pub const GTPV2C_CREATE_SESSION_REQ: u8 = 		                    32;
pub const GTPV2C_CREATE_SESSION_RSP: u8 = 		                    33;
pub const GTPV2C_DELETE_SESSION_REQ: u8 = 		                    36;
pub const GTPV2C_DELETE_SESSION_RSP: u8 = 		                    37;

// SGSN/MME to PGW (S4/S11, S5/S8)
pub const GTPV2C_MODIFY_BEARER_REQ: u8 = 		                    34;
pub const GTPV2C_MODIFY_BEARER_RSP: u8 = 		                    35;
pub const GTPV2C_CHANGE_NTF_REQ: u8 = 		                        38;
pub const GTPV2C_CHANGE_NTF_RSP: u8 = 		                        39;
pub const GTPV2C_RESUME_NTF: u8 = 		                            164;
pub const GTPV2C_RESUME_ACK: u8 = 		                            165;

// Messages without explicit response
pub const GTPV2C_MODIFY_BEARER_CMD: u8 = 		                    64; 		/* MME/SGSN/ePDG to PGW - S11/S4, S5/S8, S2b */
pub const GTPV2C_MODIFY_BEARER_FAILURE_IND: u8 = 		            65; 		/* PGW to MME/SGSN/ePDG - S5/S8, S11/S4, S2b */
pub const GTPV2C_DELETE_BEARER_CMD: u8 = 		                    66; 		/* MME/SGSN to PGW - S11/S4, S5/S8 */
pub const GTPV2C_DELETE_BEARER_FAILURE_IND: u8 = 		            67; 		/* PGW to MME/SGSN -S5/S8, S11/S4 */
pub const GTPV2C_BEARER_RESOURCE_CMD: u8 = 		                	68; 		/* MME/SGSN to PGW - S11/S4, S5/S8 */
pub const GTPV2C_BEARER_RESOURCE_FAILURE_IND: u8 = 	            	69; 		/* PGW to MME/SGSN -S5/S8, S11/S4 */
pub const GTPV2C_DOWNLINK_DATA_NOTIFICATION_FAILURE_IND: u8 = 		70; 		/* SGSN/MME to SGW - S4/S11 */
pub const GTPV2C_TRACE_SESSION_ACTIVATION: u8 = 		            71; 		/* MME/SGSN/ePDG to PGW - S11/S4, S5/S8, S2b */
pub const GTPV2C_TRACE_SESSION_DEACTIVATION: u8 = 		            72; 		/* MME/SGSN/ePDG to PGW - S11/S4, S5/S8, S2b */
pub const GTPV2C_STOP_PAGING_IND: u8 = 		                    	73; 		/* SGW to MME/SGSN - S11/S4 */

// PGW to SGSN/MME/ePDG (S5/S8, S4/S11, S2b)
pub const GTPV2C_CREATE_BEARER_REQ: u8 = 		                    95;
pub const GTPV2C_CREATE_BEARER_RSP: u8 = 		                    96;
pub const GTPV2C_UPDATE_BEARER_REQ: u8 = 		                    97;
pub const GTPV2C_UPDATE_BEARER_RSP: u8 = 		                    98;
pub const GTPV2C_DELETE_BEARER_REQ: u8 = 		                    99;
pub const GTPV2C_DELETE_BEARER_RSP: u8 = 		                    100;

// PGW to MME, MME to PGW, SGW to PGW, SGW to MME, PGW to ePDG, ePDG to PGW (S5/S8, S11, S2b)
pub const GTPV2C_DELETE_PDN_CONNECTION_SET_REQ: u8 = 		        101;
pub const GTPV2C_DELETE_PDN_CONNECTION_SET_RSP: u8 = 		        102;

// MME to MME, SGSN to MME, MME to SGSN, SGSN to SGSN (S3/S10/S16)
pub const GTPV2C_IDENTIFICATION_REQ: u8 = 		                    128;
pub const GTPV2C_IDENTIFICATION_RSP: u8 = 		                    129;
pub const GTPV2C_CONTEXT_REQ: u8 = 		                        	130;
pub const GTPV2C_CONTEXT_RSP: u8 = 		                        	131;
pub const GTPV2C_CONTEXT_ACK: u8 = 		                        	132;
pub const GTPV2C_FORWARD_RELOCATION_REQ: u8 = 		                133;
pub const GTPV2C_FORWARD_RELOCATION_RSP: u8 = 		                134;
pub const GTPV2C_FORWARD_RELOCATION_COMPLETE_NTF: u8 = 		    	135;
pub const GTPV2C_FORWARD_RELOCATION_COMPLETE_ACK: u8 = 		    	136;
pub const GTPV2C_FORWARD_ACCESS_CONTEXT_NTF: u8 = 		            137;
pub const GTPV2C_FORWARD_ACCESS_CONTEXT_ACK: u8 = 		            138;
pub const GTPV2C_RELOCATION_CANCEL_REQ: u8 = 		                139;
pub const GTPV2C_RELOCATION_CANCEL_RSP: u8 = 		                140;
pub const GTPV2C_CONFIGURE_TRANSFER_TUNNEL: u8 = 		            141;
pub const GTPV2C_RAN_INFORMATION_RELAY: u8 = 		                152;

// SGSN to MME, MME to SGSN (S3)
pub const GTPV2C_DETACH_NTF: u8 = 		                            149;
pub const GTPV2C_DETACH_ACK: u8 = 		                            150;
pub const GTPV2C_CS_PAGING_INDICATION: u8 = 		                151;
pub const GTPV2C_ALERT_MME_NTF: u8 = 		                        153;
pub const GTPV2C_ALERT_MME_ACK: u8 = 		                        154;
pub const GTPV2C_UE_ACTIVITY_NTF: u8 = 		                    	155;
pub const GTPV2C_UE_ACTIVITY_ACK: u8 = 		                    	156;

// SGSN/MME to SGW, SGSN to MME (S4/S11/S3)
// SGSN to SGSN (S16), SGW to PGW (S5/S8)
pub const GTPV2C_SUSPEND_NTF: u8 = 		                        	162;
pub const GTPV2C_SUSPEND_ACK: u8 = 		                        	163;

// SGSN/MME to SGW (S4/S11)
pub const GTPV2C_CREATE_FORWARDING_TUNNEL_REQ: u8 = 		        160;
pub const GTPV2C_CREATE_FORWARDING_TUNNEL_RSP: u8 = 		        161;
pub const GTPV2C_CREATE_INDIRECT_DATA_FORWARD_TUNNEL_REQ: u8 = 		166;
pub const GTPV2C_CREATE_INDIRECT_DATA_FORWARD_TUNNEL_RSP: u8 = 		167;
pub const GTPV2C_DELETE_INDIRECT_DATA_FORWARD_TUNNEL_REQ: u8 = 		168;
pub const GTPV2C_DELETE_INDIRECT_DATA_FORWARD_TUNNEL_RSP: u8 = 		169;
pub const GTPV2C_RELEASE_ACCESS_BEARERS_REQ: u8 = 		            170;
pub const GTPV2C_RELEASE_ACCESS_BEARERS_RSP: u8 = 		            171;

// SGW to SGSN/MME (S4/S11)
pub const GTPV2C_DOWNLINK_DATA_NOTIFICATION: u8 = 		            176;
pub const GTPV2C_DOWNLINK_DATA_NOTIFICATION_ACK: u8 = 		        177;
pub const GTPV2C_PGW_RESTART_NOTIFICATION: u8 = 		            179;
pub const GTPV2C_PGW_RESTART_NOTIFICATION_ACK: u8 = 		        180;

// SGW to PGW, PGW to SGW (S5/S8)
pub const GTPV2C_UPDATE_PDN_CONNECTION_SET_REQ: u8 = 		        200;
pub const GTPV2C_UPDATE_PDN_CONNECTION_SET_RSP: u8 = 		        201;

// MME to SGW (S11)
pub const GTPV2C_MODIFY_ACCESS_BEARERS_REQ: u8 = 		            211;
pub const GTPV2C_MODIFY_ACCESS_BEARERS_RSP: u8 = 		            212;

// MBMS GW to MME/SGSN (Sm/Sn)
pub const GTPV2C_MBMS_SESSION_START_REQ: u8 = 		                231;
pub const GTPV2C_MBMS_SESSION_START_RSP: u8 = 		                232;
pub const GTPV2C_MBMS_SESSION_UPDATE_REQ: u8 = 		            	233;
pub const GTPV2C_MBMS_SESSION_UPDATE_RSP: u8 = 		            	234;
pub const GTPV2C_MBMS_SESSION_STOP_REQ: u8 = 		                235;
pub const GTPV2C_MBMS_SESSION_STOP_RSP: u8 = 		                236;
pub const GTPV2C_MSG_MAX: u8 = 		                            	255;


// GTPv2-C Information Element Type Values
pub const GTPV2C_IE_RESERVED: u8 =								0;
pub const GTPV2C_IE_IMSI: u8 =									1; 		/* International Mobile Subscriber Identity */
pub const GTPV2C_IE_CAUSE: u8 =									2;
pub const GTPV2C_IE_RECOVERY: u8 =								3; 		/* Restart Counter */
 		/* Reserved for S101 interface 		4 to 50 */
pub const GTPV2C_IE_STN_SR: u8 =								51;
 		/* Reserved for Sv interface 		52 to 70 */
pub const GTPV2C_IE_APN: u8 =									71; 		/* Access Point Name */
pub const GTPV2C_IE_AMBR: u8 = 		                            72; 		/* Aggregate Maximum Bit Rate */
pub const GTPV2C_IE_EBI: u8 =									73; 		/* EPS Bearer ID */
pub const GTPV2C_IE_IP_ADDRESS: u8 =							74;
pub const GTPV2C_IE_MEI: u8 =									75; 		/* Mobile Equipment Identity */
pub const GTPV2C_IE_MSISDN: u8 =								76;
pub const GTPV2C_IE_INDICATION: u8 =							77;
pub const GTPV2C_IE_PCO: u8 =									78; 		/* Protocol Configuration Options */
pub const GTPV2C_IE_PAA: u8 =									79; 		/* PDN Address Allocation */
pub const GTPV2C_IE_BEARER_QOS: u8 =							80; 		/* Bearer Level Quality of Service */
pub const GTPV2C_IE_FLOW_QOS: u8 =								81; 		/* Flow Quality of Service */
pub const GTPV2C_IE_RAT_TYPE: u8 =								82;
pub const GTPV2C_IE_SERVING_NETWORK: u8 =						83;
pub const GTPV2C_IE_BEARER_TFT: u8 =							84; 		/* EPS Bearer Level Traffic Flow Template */
pub const GTPV2C_IE_TAD: u8 =									85; 		/* Traffic Aggregation Description */
pub const GTPV2C_IE_ULI: u8 =									86; 		/* User Location Information */
pub const GTPV2C_IE_FTEID: u8 =									87; 		/* Fully Qualified Tunnel Endpoint Identifier */
pub const GTPV2C_IE_TMSI: u8 =									88;
pub const GTPV2C_IE_GLOBAL_CN_ID: u8 =							89;
pub const GTPV2C_IE_S103PDF: u8 =								90; 		/* S103 PDN Data Forwarding Info */
pub const GTPV2C_IE_S1UDF: u8 =									91; 		/* S1-U Data Forwarding Info */
pub const GTPV2C_IE_DELAY_VALUE: u8 =							92;
pub const GTPV2C_IE_BEARER_CONTEXT: u8 =						93;
pub const GTPV2C_IE_CHARGING_ID: u8 =							94;
pub const GTPV2C_IE_CHARGING_CHARACTERISTICS: u8 =				95;
pub const GTPV2C_IE_TRACE_INFORMATION: u8 =						96;
pub const GTPV2C_IE_BEARER_FLAGS: u8 =							97;
 		/* Reserved: u8 = 		98 */
pub const GTPV2C_IE_PDN_TYPE: u8 =								99;
pub const GTPV2C_IE_PROCEDURE_TRANSACTION_ID: u8 =				100;
pub const GTPV2C_IE_DRX_PARAMETER: u8 =							101;
 		/* Reserved 		102 */
 		/* MM Context 		103 to 108 */
pub const GTPV2C_IE_PDN_CONNECTION: u8 =						109;
pub const GTPV2C_IE_PDU_NUMBERS: u8 =							110;
pub const GTPV2C_IE_PTMSI: u8 =									111;
pub const GTPV2C_IE_PTMSI_SIGNATURE: u8 =						112;
pub const GTPV2C_IE_HOP_COUNTER: u8 =							113;
pub const GTPV2C_IE_UE_TIME_ZONE: u8 =							114;
pub const GTPV2C_IE_TRACE_REFERENCE: u8 =						115;
pub const GTPV2C_IE_COMPLETE_REQUEST_MESSAGE: u8 =				116;
pub const GTPV2C_IE_GUTI: u8 =									117;
pub const GTPV2C_IE_F_CONTAINER: u8 =							118;
pub const GTPV2C_IE_F_CAUSE: u8 =								119;
pub const GTPV2C_IE_SELECTED_PLMN_ID: u8 =						120;
pub const GTPV2C_IE_TARGET_IDENTIFICATION: u8 =					121;
 		/* Reserved 		122 */
pub const GTPV2C_IE_PACKET_FLOW_ID: u8 =						123;
pub const GTPV2C_IE_RAB_CONTEXT: u8 =							124;
pub const GTPV2C_IE_SOURCE_RNC_PDCP_CONTEXT_INFO: u8 =			125;
pub const GTPV2C_IE_UDP_SOURCE_PORT_NUMBER: u8 =				126;
pub const GTPV2C_IE_APN_RESTRICTION: u8 =						127;
pub const GTPV2C_IE_SELECTION_MODE: u8 =						128;
pub const GTPV2C_IE_SOURCE_IDENTIFICATION: u8 =					129;
 		/* Reserved 		130 */
pub const GTPV2C_IE_CHANGE_REPORTING_ACTION: u8 =				131;
pub const GTPV2C_IE_FQ_CSID: u8 =								132; 		/* Fully Qualified PDN Connection Set Identifier */
pub const GTPV2C_IE_CHANNEL_NEEDED: u8 =						133;
pub const GTPV2C_IE_EMLPP_PRIORITY: u8 =						134;
pub const GTPV2C_IE_NODE_TYPE: u8 =								135;
pub const GTPV2C_IE_FQDN: u8 =									136; 		/* Fully Qualified Domain Name */
pub const GTPV2C_IE_TI: u8 =									137; 		/* Transaction Identifier */
pub const GTPV2C_IE_MBMS_SESSION_DURATION: u8 =					138;
pub const GTPV2C_IE_MBMS_SERIVCE_AREA: u8 =						139;
pub const GTPV2C_IE_MBMS_SESSION_IDENTIFIER: u8 =				140;
pub const GTPV2C_IE_MBMS_FLOW_IDENTIFIER: u8 =					141;
pub const GTPV2C_IE_MBMS_IP_MULTICAST_DISTRIBUTION: u8 =		142;
pub const GTPV2C_IE_MBMS_DISTRIBUTION_ACK: u8 =					143;
pub const GTPV2C_IE_RFSP_INDEX: u8 =							144;
pub const GTPV2C_IE_UCI: u8 =									145; 		/* User CSG Information */
pub const GTPV2C_IE_CSG_INFORMATION_REPORTING_ACTION: u8 =		146;
pub const GTPV2C_IE_CSG_ID: u8 =								147;
pub const GTPV2C_IE_CMI: u8 =									148; 		/* CSG Membership Indication */
pub const GTPV2C_IE_SERVICE_INDICATOR: u8 =						149;
pub const GTPV2C_IE_DETACH_TYPE: u8 =							150;
pub const GTPV2C_IE_LDN: u8 =									151; 		/* Local Distiguished Name */
pub const GTPV2C_IE_NODE_FEATURES: u8 =							152;
pub const GTPV2C_IE_MBMS_TIME_TO_DATA_TRANSFER: u8 =			153;
pub const GTPV2C_IE_THROTTING: u8 =								154;
pub const GTPV2C_IE_ARP: u8 =									155; 		/* Allocation/Retention Priority */
pub const GTPV2C_IE_EPC_TIMER: u8 =								156;
pub const GTPV2C_IE_SIGNALLING_PRIORITY_INDICATION: u8 =		157;
pub const GTPV2C_IE_TMGI: u8 =									158; 		/* Temporary Mobile Group Identity */
pub const GTPV2C_IE_ADDITIONAL_MM_CONTEXT_FOR_SRVCC: u8 =		159;
pub const GTPV2C_IE_ADDITIONAL_FLAGS_FOR_SRVCC: u8 =			160;
pub const GTPV2C_IE_MMBR: u8 =									161; 		/* Max MBR/APN-AMBR */
pub const GTPV2C_IE_MDT_CONFIGURATION: u8 =						162;
pub const GTPV2C_IE_APCO: u8 =									163; 		/* Additional Protocol Configuration Options */
 		/* Spare. For future use. 		164 to 254 */
pub const GTPV2C_IE_PRIVATE_EXTENSION: u8 =						255;
pub const GTPV2C_IE_TYPE_MAX: u8 =								255;


// GTPv2 Error Types
pub const 	GTPV2C_CAUSE_RESERVED	: u8 =							1;
pub const 	GTPV2C_CAUSE_LOCAL_DETACH	: u8 =						2;
pub const 	GTPV2C_CAUSE_COMPLETE_DETACH	: u8 =					3;
pub const 	GTPV2C_CAUSE_RAT_CHANGED_NON_3GPP	: u8 =				4;
pub const 	GTPV2C_CAUSE_ISR_DEACTIVATION	: u8 =					5;
pub const 	GTPV2C_CAUSE_ERROR_INDICATION_RECEIVED	: u8 =			6;
pub const 	GTPV2C_CAUSE_IMSI_DETACH_ONLY	: u8 =					7;
pub const 	GTPV2C_CAUSE_REACTIVATION_REQUESTED	: u8 =				8;
pub const 	GTPV2C_CAUSE_PDN_RECONNECTION_DISALLOWED	: u8 =		9;
pub const 	GTPV2C_CAUSE_ACCESS_CHANGED_TO_3GPP	: u8 =				10;
pub const 	GTPV2C_CAUSE_INACTIVITY_TIMER_EXPIRES	: u8 =			11;
pub const 	GTPV2C_CAUSE_REQUEST_ACCEPTED	: u8 =					16;
pub const 	GTPV2C_CAUSE_REQUEST_ACCEPTED_PARTIALLY	: u8 =			17;
pub const 	GTPV2C_CAUSE_NEW_PDN_TYPE_NETWORK_PERFERENCE	: u8 =	18;
pub const 	GTPV2C_CAUSE_NEW_PDN_TPYE_SINGLE_ADDRESS_ONLY	: u8 =	20;
pub const 	GTPV2C_CAUSE_CONTEXT_NOT_FOUND	: u8 =					64;
pub const 	GTPV2C_CAUSE_INVALID_MESSAGE_FORMAT	: u8 =				65;
pub const 	GTPV2C_CAUSE_VERSION_NOT_SUPPORTED_BY_NEXT_PEER	: u8 =	66;
pub const 	GTPV2C_CAUSE_INVALID_LENGTH	: u8 =						67;
pub const 	GTPV2C_CAUSE_SERVICE_NOT_SUPPORTED	: u8 =				68;
pub const 	GTPV2C_CAUSE_MANDATORY_IE_INCORRECT	: u8 =				69;
pub const 	GTPV2C_CAUSE_MANDATORY_IE_MISSING	: u8 =				70;
pub const 	GTPV2C_CAUSE_SYSTEM_FAILURE	: u8 =						72;
pub const 	GTPV2C_CAUSE_NO_RESOURCES_AVAILABLE	: u8 =				73;
pub const 	GTPV2C_CAUSE_SEMANTIC_ERROR_IN_TFT	: u8 =				74;
pub const 	GTPV2C_CAUSE_SYNTACTIC_ERROR_IN_TFT	: u8 =				75;
pub const 	GTPV2C_CAUSE_SEMANTIC_ERROR_IN_PACKET_FILTER	: u8 =	76;
pub const 	GTPV2C_CAUSE_SYNTACTIC_ERROR_IN_PACKET_FILTER	: u8 =	77;
pub const 	GTPV2C_CAUSE_MISSING_OR_UNKNOWN_APN	: u8 =				78;
pub const 	GTPV2C_CAUSE_GRE_KEY_NOT_FOUND	: u8 =					80;
pub const 	GTPV2C_CAUSE_RELOCATION_FAILURE	: u8 =					81;
pub const 	GTPV2C_CAUSE_DENIED_IN_RAT	: u8 =						82;
pub const 	GTPV2C_CAUSE_PREFERRED_PDN_TYPE_NOT_SUPPORTED	: u8 =	83;
pub const 	GTPV2C_CAUSE_ALL_DYNAMIC_ADDRESSES_ARE_OCCUPIED	: u8 =	84;
pub const 	GTPV2C_CAUSE_UE_CONTEXT_WITHOUT_TFT	: u8 =				85;
pub const 	GTPV2C_CAUSE_PROTOCOL_TYPE_NOT_SUPPORTED	: u8 =		86;
pub const 	GTPV2C_CAUSE_UE_NOT_RESPONDING	: u8 =					87;
pub const 	GTPV2C_CAUSE_UE_REFUSES	: u8 =							88;
pub const 	GTPV2C_CAUSE_SERVICE_DENIED	: u8 =						89;
pub const 	GTPV2C_CAUSE_UNABLE_TO_PAGE_UE	: u8 =					90;
pub const 	GTPV2C_CAUSE_NO_MEMORY_AVAILABLE	: u8 =				91;
pub const 	GTPV2C_CAUSE_USER_AUTHENTICATION_FAILED	: u8 =			92;
pub const 	GTPV2C_CAUSE_APN_ACCESS_DENIED	: u8 =					93;
pub const 	GTPV2C_CAUSE_REQUEST_REJECTED	: u8 =					94;
pub const 	GTPV2C_CAUSE_PTMSI_SIGNATURE_MISMATCH	: u8 =			95;
pub const 	GTPV2C_CAUSE_IMSI_IMEI_NOT_KNOWN	: u8 =				96;
pub const 	GTPV2C_CAUSE_SEMANTIC_ERROR_IN_TAD	: u8 =				97;
pub const 	GTPV2C_CAUSE_SYNTACTIC_ERROR_IN_TAD	: u8 =				98;
pub const 	GTPV2C_CAUSE_REMOTE_PEER_NOT_RESPONDING	: u8 =			100;
pub const 	GTPV2C_CAUSE_COLLISION	: u8 =							101;
pub const 	GTPV2C_CAUSE_UNABLE_TO_PAGE_UE_SUSPENSION	: u8 =		102;
pub const 	GTPV2C_CAUSE_CONDITIONAL_IE_MISSING	: u8 =				103;
pub const 	GTPV2C_CAUSE_APN_RESTRICTION_TYPE_INCOMPATIBLE	: u8 =	104;
pub const 	GTPV2C_CAUSE_INVALID_OVERALL_LENGTH	: u8 =				105;
pub const 	GTPV2C_CAUSE_DATA_FORWARDING_NOT_SUPPORTED	: u8 =		106;
pub const 	GTPV2C_CAUSE_INVALID_REPLY_FROM_REMOTE_PEER	: u8 =		107;
pub const 	GTPV2C_CAUSE_FALLBACK_TO_GTPV1	: u8 =					108;
pub const 	GTPV2C_CAUSE_INVALID_PEER	: u8 =						109;
pub const 	GTPV2C_CAUSE_TEMPORARILY_REJECTED	: u8 =				110;
pub const 	GTPV2C_CAUSE_MODIFICATIONS_NOT_LIMITED_TO_S1_U	: u8 =	111;
pub const 	GTPV2C_CAUSE_REQUEST_REJECTED_FOR_PMIPV6_REASON	: u8 =	112;
pub const 	GTPV2C_CAUSE_APN_CONGESTION	: u8 =						113;
pub const 	GTPV2C_CAUSE_BEARER_HANDLING_NOT_SUPPORTED	: u8 =		114;
pub const 	GTPV2C_CAUSE_UE_ALREADY_RE_ATTACHED	: u8 =				115;
pub const 	GTPV2C_CAUSE_MULTIPLE_PDN_NOT_ALLOWED	: u8 =			116;
pub const 	GTPV2C_CAUSE_MAX	: u8 =								255;



pub static GTPV2_MSG_TYPES: [&str; 256] = [
// pub static GTPV2_MSG_TYPES: [&'static str; 256] = [
/* 0 */		"Reserved",
/* 1 */		"Echo Request",
/* 2 */		"Echo Response",
/* 3 */		"Version Not Supported Indication",
/* 4 */		"Unknown",
/* 5 */		"Unknown",
/* 6 */		"Unknown",
/* 7 */		"Unknown",
/* 8 */		"Unknown",
/* 9 */		"Unknown",
/* 10 */	"Unknown",
/* 11 */	"Unknown",
/* 12 */	"Unknown",
/* 13 */	"Unknown",
/* 14 */	"Unknown",
/* 15 */	"Unknown",
/* 16 */	"Unknown",
/* 17 */	"Unknown",
/* 18 */	"Unknown",
/* 19 */	"Unknown",
/* 20 */	"Unknown",
/* 21 */	"Unknown",
/* 22 */	"Unknown",
/* 23 */	"Unknown",
/* 24 */	"Unknown",
/* 25 */	"Unknown",
/* 26 */	"Unknown",
/* 27 */	"Unknown",
/* 28 */	"Unknown",
/* 29 */	"Unknown",
/* 30 */	"Unknown",
/* 31 */	"Unknown",
/* 32 */	"Create Session Request",
/* 33 */	"Create Session Response",
/* 34 */	"Modify Bearer Request",
/* 35 */	"Modify Bearer Response",
/* 36 */	"Delete Session Request",
/* 37 */	"Delete Session Response",
/* 38 */	"Change Notification Request",
/* 39 */	"Change Notification Response",
/* 40 */	"Remote UE Report Notification",
/* 41 */	"Remote UE Report Acknowledge",
/* 42 */	"Unknown",
/* 43 */	"Unknown",
/* 44 */	"Unknown",
/* 45 */	"Unknown",
/* 46 */	"Unknown",
/* 47 */	"Unknown",
/* 48 */	"Unknown",
/* 49 */	"Unknown",
/* 50 */	"Unknown",
/* 51 */	"Unknown",
/* 52 */	"Unknown",
/* 53 */	"Unknown",
/* 54 */	"Unknown",
/* 55 */	"Unknown",
/* 56 */	"Unknown",
/* 57 */	"Unknown",
/* 58 */	"Unknown",
/* 59 */	"Unknown",
/* 60 */	"Unknown",
/* 61 */	"Unknown",
/* 62 */	"Unknown",
/* 63 */	"Unknown",
/* 64 */	"Modify Bearer Command",
/* 65 */	"Modify Bearer Failure Indication",
/* 66 */	"Delete Bearer Command",
/* 67 */	"Delete Bearer Failure Indication",
/* 68 */	"Bearer Resource Command",
/* 69 */	"Bearer Resource Failure Indication",
/* 70 */	"Downlink Data Notification Failure Indication",
/* 71 */	"Trace Session Activation",
/* 72 */	"Trace Session Deactivation",
/* 73 */	"Stop Paging Indication",
/* 74 */	"Unknown",
/* 75 */	"Unknown",
/* 76 */	"Unknown",
/* 77 */	"Unknown",
/* 78 */	"Unknown",
/* 79 */	"Unknown",
/* 80 */	"Unknown",
/* 81 */	"Unknown",
/* 82 */	"Unknown",
/* 83 */	"Unknown",
/* 84 */	"Unknown",
/* 85 */	"Unknown",
/* 86 */	"Unknown",
/* 87 */	"Unknown",
/* 88 */	"Unknown",
/* 89 */	"Unknown",
/* 90 */	"Unknown",
/* 91 */	"Unknown",
/* 92 */	"Unknown",
/* 93 */	"Unknown",
/* 94 */	"Unknown",
/* 95 */	"Create Bearer Request",
/* 96 */	"Create Bearer Response",
/* 97 */	"Update Bearer Request",
/* 98 */	"Update Bearer Response",
/* 99 */	"Delete Bearer Request",
/* 100 */	"Delete Bearer Response",
/* 101 */	"Delete PDN Connection Set Request",
/* 102 */	"Delete PDN Connection Set Response",
/* 103 */	"PGW Downlink Triggering Notification",
/* 104 */	"PGW Downlink Triggering Acknowledge",
/* 105 */	"Unknown",
/* 106 */	"Unknown",
/* 107 */	"Unknown",
/* 108 */	"Unknown",
/* 109 */	"Unknown",
/* 110 */	"Unknown",
/* 111 */	"Unknown",
/* 112 */	"Unknown",
/* 113 */	"Unknown",
/* 114 */	"Unknown",
/* 115 */	"Unknown",
/* 116 */	"Unknown",
/* 117 */	"Unknown",
/* 118 */	"Unknown",
/* 119 */	"Unknown",
/* 120 */	"Unknown",
/* 121 */	"Unknown",
/* 122 */	"Unknown",
/* 123 */	"Unknown",
/* 124 */	"Unknown",
/* 125 */	"Unknown",
/* 126 */	"Unknown",
/* 127 */	"Unknown",
/* 128 */	"Identification Request",
/* 129 */	"Identification Response",
/* 130 */	"Context Request",
/* 131 */	"Context Response",
/* 132 */	"Context Acknowledge",
/* 133 */	"Forward Relocation Request",
/* 134 */	"Forward Relocation Response",
/* 135 */	"Forward Relocation Complete Notification",
/* 136 */	"Forward Relocation Complete Acknowledge",
/* 137 */	"Forward Access Context Notification",
/* 138 */	"Forward Access Context Acknowledge",
/* 139 */	"Relocation Cancel Request",
/* 140 */	"Relocation Cancel Response",
/* 141 */	"Configuration Transfer Tunnel",
/* 142 */	"Unknown",
/* 143 */	"Unknown",
/* 144 */	"Unknown",
/* 145 */	"Unknown",
/* 146 */	"Unknown",
/* 147 */	"Unknown",
/* 148 */	"Unknown",
/* 149 */	"Detach Notification",
/* 150 */	"Detach Acknowledge",
/* 151 */	"CS Paging Indication",
/* 152 */	"RAN Information Relay",
/* 153 */	"Alert MME Notification",
/* 154 */	"Alert MME Acknowledge",
/* 155 */	"UE Activity Notification",
/* 156 */	"UE Activity Acknowledge",
/* 157 */	"ISR Status Indication",
/* 158 */	"UE Registration Query Request",
/* 159 */	"UE Registration Query Response",
/* 160 */	"Create Forwarding Tunnel Request",
/* 161 */	"Create Forwarding Tunnel Response",
/* 162 */	"Suspend Notification",
/* 163 */	"Suspend Acknowledge",
/* 164 */	"Resume Notification",
/* 165 */	"Resume Acknowledge",
/* 166 */	"Create Indirect Data Forwarding Tunnel Request",
/* 167 */	"Create Indirect Data Forwarding Tunnel Response",
/* 168 */	"Delete Indirect Data Forwarding Tunnel Request",
/* 169 */	"Delete Indirect Data Forwarding Tunnel Response",
/* 170 */	"Release Access Bearers Request",
/* 171 */	"Release Access Bearers Response",
/* 172 */	"Unknown",
/* 173 */	"Unknown",
/* 174 */	"Unknown",
/* 175 */	"Unknown",
/* 176 */	"Downlink Data Notification",
/* 177 */	"Downlink Data Notification Acknowledgement",
/* 178 */	"Unknown",
/* 179 */	"PGW Restart Notification",
/* 180 */	"PGW Restart Notification Acknowledge",
/* 181 */	"Unknown",
/* 182 */	"Unknown",
/* 183 */	"Unknown",
/* 184 */	"Unknown",
/* 185 */	"Unknown",
/* 186 */	"Unknown",
/* 187 */	"Unknown",
/* 188 */	"Unknown",
/* 189 */	"Unknown",
/* 190 */	"Unknown",
/* 191 */	"Unknown",
/* 192 */	"Unknown",
/* 193 */	"Unknown",
/* 194 */	"Unknown",
/* 195 */	"Unknown",
/* 196 */	"Unknown",
/* 197 */	"Unknown",
/* 198 */	"Unknown",
/* 199 */	"Unknown",
/* 200 */	"Update PDN Connection Set Request",
/* 201 */	"Update PDN Connection Set Response",
/* 202 */	"Unknown",
/* 203 */	"Unknown",
/* 204 */	"Unknown",
/* 205 */	"Unknown",
/* 206 */	"Unknown",
/* 207 */	"Unknown",
/* 208 */	"Unknown",
/* 209 */	"Unknown",
/* 210 */	"Unknown",
/* 211 */	"Modify Access Bearers Request",
/* 212 */	"Modify Access Bearers Response",
/* 213 */	"Unknown",
/* 214 */	"Unknown",
/* 215 */	"Unknown",
/* 216 */	"Unknown",
/* 217 */	"Unknown",
/* 218 */	"Unknown",
/* 219 */	"Unknown",
/* 220 */	"Unknown",
/* 221 */	"Unknown",
/* 222 */	"Unknown",
/* 223 */	"Unknown",
/* 224 */	"Unknown",
/* 225 */	"Unknown",
/* 226 */	"Unknown",
/* 227 */	"Unknown",
/* 228 */	"Unknown",
/* 229 */	"Unknown",
/* 230 */	"Unknown",
/* 231 */	"MBMS Session Start Request",
/* 232 */	"MBMS Session Start Response",
/* 233 */	"MBMS Session Update Request",
/* 234 */	"MBMS Session Update Response",
/* 235 */	"MBMS Session Stop Request",
/* 236 */	"MBMS Session Stop Response",
/* 237 */	"Unknown",
/* 238 */	"Unknown",
/* 239 */	"Unknown",
/* 240 */	"Unknown",
/* 241 */	"Unknown",
/* 242 */	"Unknown",
/* 243 */	"Unknown",
/* 244 */	"Unknown",
/* 245 */	"Unknown",
/* 246 */	"Unknown",
/* 247 */	"Unknown",
/* 248 */	"Unknown",
/* 249 */	"Unknown",
/* 250 */	"Unknown",
/* 251 */	"Unknown",
/* 252 */	"Unknown",
/* 253 */	"Unknown",
/* 254 */	"Unknown",
/* 255 */	"Unknown",
];

pub static GTPV2_IE_TYPES: [&str;256] = [
/* 0 */		"Reserved",
/* 1 */		"International Mobile Subscriber Identity (IMSI)",
/* 2 */		"Cause",
/* 3 */		"Recovery (Restart Counter)",
/* 4 */		"Unknown",
/* 5 */		"Unknown",
/* 6 */		"Unknown",
/* 7 */		"Unknown",
/* 8 */		"Unknown",
/* 9 */		"Unknown",
/* 10 */	"Unknown",
/* 11 */	"Unknown",
/* 12 */	"Unknown",
/* 13 */	"Unknown",
/* 14 */	"Unknown",
/* 15 */	"Unknown",
/* 16 */	"Unknown",
/* 17 */	"Unknown",
/* 18 */	"Unknown",
/* 19 */	"Unknown",
/* 20 */	"Unknown",
/* 21 */	"Unknown",
/* 22 */	"Unknown",
/* 23 */	"Unknown",
/* 24 */	"Unknown",
/* 25 */	"Unknown",
/* 26 */	"Unknown",
/* 27 */	"Unknown",
/* 28 */	"Unknown",
/* 29 */	"Unknown",
/* 30 */	"Unknown",
/* 31 */	"Unknown",
/* 32 */	"Unknown",
/* 33 */	"Unknown",
/* 34 */	"Unknown",
/* 35 */	"Unknown",
/* 36 */	"Unknown",
/* 37 */	"Unknown",
/* 38 */	"Unknown",
/* 39 */	"Unknown",
/* 40 */	"Unknown",
/* 41 */	"Unknown",
/* 42 */	"Unknown",
/* 43 */	"Unknown",
/* 44 */	"Unknown",
/* 45 */	"Unknown",
/* 46 */	"Unknown",
/* 47 */	"Unknown",
/* 48 */	"Unknown",
/* 49 */	"Unknown",
/* 50 */	"Unknown",
/* 51 */	"STN-SR",
/* 52 */	"Unknown",
/* 53 */	"Unknown",
/* 54 */	"Unknown",
/* 55 */	"Unknown",
/* 56 */	"SRVCC Cause",
/* 57 */	"Unknown",
/* 58 */	"Unknown",
/* 59 */	"Unknown",
/* 60 */	"Unknown",
/* 61 */	"Unknown",
/* 62 */	"Unknown",
/* 63 */	"Unknown",
/* 64 */	"Unknown",
/* 65 */	"Unknown",
/* 66 */	"Unknown",
/* 67 */	"Unknown",
/* 68 */	"Unknown",
/* 69 */	"Unknown",
/* 70 */	"Unknown",
/* 71 */	"Access Point Name (APN)",
/* 72 */	"Aggregate Maximum Bit Rate (AMBR)",
/* 73 */	"EPS Bearer ID (EBI)",
/* 74 */	"IP Address",
/* 75 */	"Mobile Equipment Identity (MEI)",
/* 76 */	"MSISDN",
/* 77 */	"Indication",
/* 78 */	"Protocol Configuration Options (PCO)",
/* 79 */	"PDN Address Allocation (PAA)",
/* 80 */	"Bearer Level Quality of Service (Bearer QoS)",
/* 81 */	"Flow Quality of Service (Flow QoS)",
/* 82 */	"RAT Type",
/* 83 */	"Serving Network",
/* 84 */	"EPS Bearer Level Traffic Flow Template (Bearer TFT)",
/* 85 */	"Traffic Aggregation Description (TAD)",
/* 86 */	"User Location Information (ULI)",
/* 87 */	"Fully Qualified Tunnel Endpoint Identifier (F-TEID)",
/* 88 */	"TMSI",
/* 89 */	"Global CN-Id",
/* 90 */	"S103 PDN Data Forwarding Info (S103PDF)",
/* 91 */	"S1-U Data Forwarding Info (S1UDF)",
/* 92 */	"Delay Value",
/* 93 */	"Bearer Context ",
/* 94 */	"Charging ID",
/* 95 */	"Charging Characteristics",
/* 96 */	"Trace Information",
/* 97 */	"Bearer Flags",
/* 98 */	"Reserved",
/* 99 */	"PDN Type",
/* 100 */	"Procedure Transaction ID",
/* 101 */	"Reserved",
/* 102 */	"Reserved",
/* 103 */	"MM Context (GSM Key and Triplets)",
/* 104 */	"MM Context (UMTS Key, Used Cipher and Quintuplets)",
/* 105 */	"MM Context (GSM Key, Used Cipher and Quintuplets)",
/* 106 */	"MM Context (UMTS Key and Quintuplets)",
/* 107 */	"MM Context (EPS Security Context, Quadruplets and Quintuplets)",
/* 108 */	"MM Context (UMTS Key, Quadruplets and Quintuplets)",
/* 109 */	"PDN Connection",
/* 110 */	"PDU Numbers",
/* 111 */	"P-TMSI",
/* 112 */	"P-TMSI Signature",
/* 113 */	"Hop Counter",
/* 114 */	"UE Time Zone",
/* 115 */	"Trace Reference",
/* 116 */	"Complete Request Message",
/* 117 */	"GUTI",
/* 118 */	"F-Container",
/* 119 */	"F-Cause",
/* 120 */	"PLMN ID",
/* 121 */	"Target Identification",
/* 122 */	"Reserved ",
/* 123 */	"Packet Flow ID ",
/* 124 */	"RAB Context ",
/* 125 */	"Source RNC PDCP Context Info",
/* 126 */	"Port Number",
/* 127 */	"APN Restriction",
/* 128 */	"Selection Mode",
/* 129 */	"Source Identification",
/* 130 */	"Reserved",
/* 131 */	"Change Reporting Action",
/* 132 */	"Fully Qualified PDN Connection Set Identifier (FQ-CSID)",
/* 133 */	"Channel needed",
/* 134 */	"eMLPP Priority",
/* 135 */	"Node Type",
/* 136 */	"Fully Qualified Domain Name (FQDN)",
/* 137 */	"Transaction Identifier (TI)",
/* 138 */	"MBMS Session Duration",
/* 139 */	"MBMS Service Area",
/* 140 */	"MBMS Session Identifier",
/* 141 */	"MBMS Flow Identifier",
/* 142 */	"MBMS IP Multicast Distribution",
/* 143 */	"MBMS Distribution Acknowledge",
/* 144 */	"RFSP Index",
/* 145 */	"User CSG Information (UCI)",
/* 146 */	"CSG Information Reporting Action",
/* 147 */	"CSG ID",
/* 148 */	"CSG Membership Indication (CMI)",
/* 149 */	"Service indicator",
/* 150 */	"Detach Type",
/* 151 */	"Local Distiguished Name (LDN)",
/* 152 */	"Node Features",
/* 153 */	"MBMS Time to Data Transfer",
/* 154 */	"Throttling",
/* 155 */	"Allocation/Retention Priority (ARP)",
/* 156 */	"EPC Timer",
/* 157 */	"Signalling Priority Indication",
/* 158 */	"Temporary Mobile Group Identity (TMGI)",
/* 159 */	"Additional MM context for SRVCC",
/* 160 */	"Additional flags for SRVCC",
/* 161 */	"Reserved",
/* 162 */	"MDT Configuration",
/* 163 */	"Additional Protocol Configuration Options (APCO)",
/* 164 */	"Absolute Time of MBMS Data Transfer",
/* 165 */	"H(e)NB Information Reporting ",
/* 166 */	"IPv4 Configuration Parameters (IP4CP)",
/* 167 */	"Change to Report Flags ",
/* 168 */	"Action Indication",
/* 169 */	"TWAN Identifier",
/* 170 */	"ULI Timestamp",
/* 171 */	"MBMS Flags",
/* 172 */	"RAN/NAS Cause",
/* 173 */	"CN Operator Selection Entity",
/* 174 */	"Trusted WLAN Mode Indication",
/* 175 */	"Node Number",
/* 176 */	"Node Identifier",
/* 177 */	"Presence Reporting Area Action",
/* 178 */	"Presence Reporting Area Information",
/* 179 */	"TWAN Identifier Timestamp",
/* 180 */	"Overload Control Information",
/* 181 */	"Load Control Information",
/* 182 */	"Metric",
/* 183 */	"Sequence Number",
/* 184 */	"APN and Relative Capacity",
/* 185 */	"WLAN Offloadability Indication",
/* 186 */	"Paging and Service Information",
/* 187 */	"Integer Number",
/* 188 */	"Millisecond Time Stamp",
/* 189 */	"Monitoring Event Information",
/* 190 */	"ECGI List",
/* 191 */	"Remote UE Context",
/* 192 */	"Remote User ID",
/* 193 */	"Remote UE IP information",
/* 194 */	"CIoT Optimizations Support Indication",
/* 195 */	"SCEF PDN Connection",
/* 196 */	"Header Compression Configuration",
/* 197 */	"Extended Protocol Configuration Options (ePCO)",
/* 198 */	"Serving PLMN Rate Control",
/* 199 */	"Counter",
/* 200 */	"Mapped UE Usage Type",
/* 201 */	"Secondary RAT Usage Data Report",
/* 202 */	"UP Function Selection Indication Flags",
/* 203 */	"Maximum Packet Loss Rate",
/* 204 */	"APN Rate Control Status",
/* 205 */	"Extended Trace Information",
/* 206 */	"Monitoring Event Extension Information",
/* 207 */	"Additional RRM Policy Index",
/* 208 */	"V2X Context",
/* 209 */	"PC5 QoS Parameters",
/* 210 */	"Services Authorized",
/* 211 */	"Bit Rate",
/* 212 */	"PC5 QoS Flow",
/* 213 */	"SGi PtP Tunnel Address",
/* 214 */	"PGW Change Info",
/* 215 */	"PGW FQDN",
/* 216 */	"Group Id",
/* 217 */	"PSCell ID",
/* 218 */	"UP Security Policy",
/* 219 */	"Alternative IMSI",
/* 220 */	"NF Instance ID",
/* 221 */	"Timer in Seconds",
/* 222 */	"Unknown",
/* 223 */	"Unknown",
/* 224 */	"Unknown",
/* 225 */	"Unknown",
/* 226 */	"Unknown",
/* 227 */	"Unknown",
/* 228 */	"Unknown",
/* 229 */	"Unknown",
/* 230 */	"Unknown",
/* 231 */	"Unknown",
/* 232 */	"Unknown",
/* 233 */	"Unknown",
/* 234 */	"Unknown",
/* 235 */	"Unknown",
/* 236 */	"Unknown",
/* 237 */	"Unknown",
/* 238 */	"Unknown",
/* 239 */	"Unknown",
/* 240 */	"Unknown",
/* 241 */	"Unknown",
/* 242 */	"Unknown",
/* 243 */	"Unknown",
/* 244 */	"Unknown",
/* 245 */	"Unknown",
/* 246 */	"Unknown",
/* 247 */	"Unknown",
/* 248 */	"Unknown",
/* 249 */	"Unknown",
/* 250 */	"Unknown",
/* 251 */	"Unknown",
/* 252 */	"Unknown",
/* 253 */	"Unknown",
/* 254 */	"Special IE type for IE Type Extension",
/* 255 */	"Private Extension"
];