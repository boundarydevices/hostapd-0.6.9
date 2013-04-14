/*
 * hostapd / Driver interface for rtl871x driver
 * Copyright (c) 2010,
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 * See README and COPYING for more details.
 */

//#define CONFIG_MGNT_L2SOCK 1
#define CONFIG_MLME_OFFLOAD 1


#include "includes.h"
#include <sys/ioctl.h>


#ifdef USE_KERNEL_HEADERS
/* compat-wireless does not include linux/compiler.h to define __user, so
 * define it here */
#ifndef __user
#define __user
#endif /* __user */
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>   /* The L2 protocols */
#include <linux/if_arp.h>
#include <linux/wireless.h>
#else /* USE_KERNEL_HEADERS */
#include <net/if_arp.h>
#include <netpacket/packet.h>
#include "wireless_copy.h"
#endif /* USE_KERNEL_HEADERS */

#include <net/if.h>


#ifndef ETH_P_80211_RAW
#define ETH_P_80211_RAW 0x0019
#endif


#include "hostapd.h"
#include "driver.h"
#include "ieee802_1x.h"
#include "eloop.h"
#include "priv_netlink.h"
#include "sta_info.h"
#include "l2_packet/l2_packet.h"

#include "wpa.h"
#include "accounting.h"
#include "ieee802_11.h"
#include "hw_features.h"
#include "radius/radius.h"

#include "driver_rtl.h"

static int rtl871x_sta_remove_ops(void *priv, const u8 *addr);
static char gbuf[4096];

struct rtl871x_driver_data {
	struct hostapd_data *hapd;
	
	char	iface[IFNAMSIZ + 1];
	int     ifindex;
	struct l2_packet_data *l2_sock; /* socket for sending eapol frames*/
	struct l2_packet_data *l2_sock_recv;/* raw packet recv socket from bridge interface*/
#ifdef CONFIG_MGNT_L2SOCK	
	struct l2_packet_data *mgnt_l2_sock; /* socket for tx/rx management frames*/
#else
	int	mgnt_sock;/* socket for tx/rx management frames*/
#endif
	int	ioctl_sock;			/* socket for ioctl() use */
	int	wext_sock;			/* socket for wireless events */
	
	int	we_version;
	u8	acct_mac[ETH_ALEN];
	
	struct hostap_sta_driver_data acct_data;
	
};

static const char *ether_sprintf(const u8 *addr)
{
	static char buf[sizeof(MACSTR)];

	if (addr != NULL)
		snprintf(buf, sizeof(buf), MACSTR, MAC2STR(addr));
	else
		snprintf(buf, sizeof(buf), MACSTR, 0,0,0,0,0,0);
	
	return buf;
}

#ifdef LINK_WITH_WIFI_REALTEK_C
extern int get_priv_func_num(int sockfd, const char *ifname, const char *fname);
extern int rtl871x_drv_set_pid_fd(int sockfd, const char *ifname, const int index, const int pid); 
#else
int get_priv_func_num(int sockfd, const char *ifname, const char *fname) {
    struct iwreq wrq;
    struct iw_priv_args *priv_ptr;
    int i, ret;

    strncpy(wrq.ifr_name, ifname, sizeof(wrq.ifr_name));
    wrq.u.data.pointer = gbuf;
    wrq.u.data.length = sizeof(gbuf) / sizeof(struct iw_priv_args);
    wrq.u.data.flags = 0;
    if ((ret = ioctl(sockfd, SIOCGIWPRIV, &wrq)) < 0) {
        wpa_printf(MSG_WARNING, "SIOCGIPRIV failed: %d", ret);
        return ret;
    }
    priv_ptr = (struct iw_priv_args *)wrq.u.data.pointer;
    for(i=0;(i < wrq.u.data.length);i++) {
        if (strcmp(priv_ptr[i].name, fname) == 0)
            return priv_ptr[i].cmd;
    }
    return -EOPNOTSUPP;
}

int rtl871x_drv_set_pid_fd(int sockfd, const char *ifname, const int index, const int pid) {
	struct iwreq wrq;
	int ret;

	int fnum;
	char *fname = "setpid";

	int req[2];

	ret = fnum = get_priv_func_num(sockfd, ifname, fname);
	if(ret < 0) {
		//LOGE("get_priv_func_num(%s) return %d", fname, ret);
		goto exit;
	}

	req[0]=index;
	req[1]=pid;

	strncpy(wrq.ifr_name, ifname, sizeof(wrq.ifr_name));
	memcpy(wrq.u.name,req,sizeof(int)*2);

	ret = ioctl(sockfd, fnum, &wrq);
	if (ret) {
		//wpa_printf(MSG_WARNING, "ioctl - failed: %d", ret);
	}
exit:
	return ret;
} 
#endif


static int rtl871x_set_iface_flags(void *priv, int dev_up, int is_mgnt)
{
	struct rtl871x_driver_data *drv = priv;
	struct ifreq ifr;
	int sockfd;

	wpa_printf(MSG_DEBUG, "%s: dev_up=%d", __func__, dev_up);

	if(is_mgnt)
		sockfd = drv->mgnt_sock;
	else
		sockfd = drv->ioctl_sock;

	if (sockfd < 0)
		return -1;
	
	memset(&ifr, 0, sizeof(ifr));
	
	if(is_mgnt) {
		//os_strlcpy(ifr.ifr_name, "mgnt.wlan", IFNAMSIZ);
		snprintf(ifr.ifr_name, IFNAMSIZ, "mgnt.%s", "wlan0");
	} else {
		os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);
	}

	if (ioctl(sockfd, SIOCGIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCGIFFLAGS]");
		return -1;
	}

	if (dev_up)
		ifr.ifr_flags |= IFF_UP;
	else
		ifr.ifr_flags &= ~IFF_UP;

	if (ioctl(sockfd, SIOCSIFFLAGS, &ifr) != 0) {
		perror("ioctl[SIOCSIFFLAGS]");
		return -1;
	}

#if 0
	if (dev_up) {
		memset(&ifr, 0, sizeof(ifr));
		os_strlcpy(ifr.ifr_name, drv->iface, IFNAMSIZ);
		ifr.ifr_mtu = HOSTAPD_MTU;
		if (ioctl(drv->ioctl_sock, SIOCSIFMTU, &ifr) != 0) {
			perror("ioctl[SIOCSIFMTU]");
			printf("Setting MTU failed - trying to survive with "
			       "current value\n");
		}
	}
#endif

	return 0;
}

static int rtl871x_hostapd_ioctl(struct rtl871x_driver_data *drv, ieee_param *param, int len)
{	
	struct iwreq iwr;

	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.data.pointer = (caddr_t) param;
	iwr.u.data.length = len;

	if (ioctl(drv->ioctl_sock, RTL_IOCTL_HOSTAPD, &iwr) < 0) {
		perror("ioctl[RTL_IOCTL_HOSTAPD]");
		return -1;
	}

	return 0;
}

static int rtl871x_notif_assoc(struct hostapd_data *hapd, const u8 *addr,
			       const u8 *ie, size_t ielen)
{
	struct sta_info *sta;
	int new_assoc, res;

	//hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
	//	       HOSTAPD_LEVEL_INFO, "associated");

	sta = ap_get_sta(hapd, addr);
	if (sta) {
		accounting_sta_stop(hapd, sta);
	} else {
		sta = ap_sta_add(hapd, addr);
		if (sta == NULL)
		{
			rtl871x_sta_remove_ops(hapd->drv_priv, addr);		
			return -1;
		}	
	}
	sta->flags &= ~(WLAN_STA_WPS | WLAN_STA_MAYBE_WPS);

	if (hapd->conf->wpa) {
		if (ie == NULL || ielen == 0) {
			if (hapd->conf->wps_state) {
				wpa_printf(MSG_DEBUG, "STA did not include "
					   "WPA/RSN IE in (Re)Association "
					   "Request - possible WPS use");
				sta->flags |= WLAN_STA_MAYBE_WPS;
				goto skip_wpa_check;
			}

			wpa_printf(MSG_DEBUG, "No WPA/RSN IE from STA");
			return -1;
		}
		if (hapd->conf->wps_state && ie[0] == 0xdd && ie[1] >= 4 &&
		    os_memcmp(ie + 2, "\x00\x50\xf2\x04", 4) == 0) {
			sta->flags |= WLAN_STA_WPS;
			goto skip_wpa_check;
		}

		if (sta->wpa_sm == NULL)
			sta->wpa_sm = wpa_auth_sta_init(hapd->wpa_auth,
							sta->addr);
		if (sta->wpa_sm == NULL) {
			wpa_printf(MSG_ERROR, "Failed to initialize WPA state "
				   "machine");
			return -1;
		}
		res = wpa_validate_wpa_ie(hapd->wpa_auth, sta->wpa_sm,
					  ie, ielen, NULL, 0);
		if (res != WPA_IE_OK) {
			wpa_printf(MSG_DEBUG, "WPA/RSN information element "
				   "rejected? (res %u)", res);
			wpa_hexdump(MSG_DEBUG, "IE", ie, ielen);
			return -1;
		}
	} else if (hapd->conf->wps_state) {
		if (ie && ielen > 4 && ie[0] == 0xdd && ie[1] >= 4 &&
		    os_memcmp(ie + 2, "\x00\x50\xf2\x04", 4) == 0) {
			sta->flags |= WLAN_STA_WPS;
		} else
			sta->flags |= WLAN_STA_MAYBE_WPS;
	}
skip_wpa_check:

	new_assoc = (sta->flags & WLAN_STA_ASSOC) == 0;
	sta->flags |= WLAN_STA_AUTH | WLAN_STA_ASSOC;
	wpa_auth_sm_event(sta->wpa_sm, WPA_ASSOC);

	hostapd_new_assoc_sta(hapd, sta, !new_assoc);

	ieee802_1x_notify_port_enabled(sta->eapol_sm, 1);

	return 0;
}

static int rtl871x_get_sta_wpaie(struct rtl871x_driver_data *drv, u8 *iebuf, u8 *addr)
{	
	struct ieee_param param;

	printf("+%s, " MACSTR " is sta's address\n", __func__, MAC2STR(addr));

	memset(&param, 0, sizeof(param));

	param.cmd = RTL871X_HOSTAPD_GET_WPAIE_STA;
	
	memcpy(param.sta_addr, addr, ETH_ALEN);
	
	if (rtl871x_hostapd_ioctl(drv, &param, sizeof(param))) {
		printf("Could not get sta wpaie from kernel driver.\n");
		return -1;
	}


	if(param.u.wpa_ie.len > 32)
		return -1;

	memcpy(iebuf, param.u.wpa_ie.reserved, param.u.wpa_ie.len);
	
	return 0;	

}

static int rtl871x_del_sta(struct rtl871x_driver_data *drv, u8 *addr)
{
	struct hostapd_data *hapd = drv->hapd;
	struct sta_info *sta;

	//hostapd_logger(hapd, addr, HOSTAPD_MODULE_IEEE80211,
	//	       HOSTAPD_LEVEL_INFO, "disassociated");

	sta = ap_get_sta(hapd, addr);
	if (sta != NULL) 
	{
		sta->flags &= ~(WLAN_STA_AUTH | WLAN_STA_ASSOC);
		wpa_auth_sm_event(sta->wpa_sm, WPA_DISASSOC);
		sta->acct_terminate_cause = RADIUS_ACCT_TERMINATE_CAUSE_USER_REQUEST;
		ieee802_1x_notify_port_enabled(sta->eapol_sm, 0);
		ap_free_sta(hapd, sta);
	}
	else
	{
		wpa_printf(MSG_DEBUG, "Disassociation notification for "
			   "unknown STA " MACSTR, MAC2STR(addr));
	}

	return 0;
	
}

static int rtl871x_new_sta(struct rtl871x_driver_data *drv, u8 *addr)
{
	struct hostapd_data *hapd = drv->hapd;
	//struct ieee80211req_wpaie ie;
	int ielen = 0, res;
	//u8 *iebuf = NULL;
	u8 iebuf[32], *piebuf=NULL;

	/*
	 * Fetch negotiated WPA/RSN parameters from the driver.
	 */
	//memset(&ie, 0, sizeof(ie));
	//memcpy(ie.wpa_macaddr, addr, IEEE80211_ADDR_LEN);
	memset(iebuf, 0 , sizeof(iebuf));
	if (rtl871x_get_sta_wpaie(drv, iebuf, addr)) {
	//if (set80211priv(drv, IEEE80211_IOCTL_GETWPAIE, &ie, sizeof(ie))) {
		
		wpa_printf(MSG_DEBUG, "%s: Failed to get WPA/RSN IE: %s",
			   __func__, strerror(errno));
		goto no_ie;
	}
	
	//wpa_hexdump(MSG_MSGDUMP, "req WPA IE",
	//	    ie.wpa_ie, IEEE80211_MAX_OPT_IE);
	
	//wpa_hexdump(MSG_MSGDUMP, "req RSN IE",
	//	    ie.rsn_ie, IEEE80211_MAX_OPT_IE);
	
	//iebuf = ie.wpa_ie;
	
/*	
	if (iebuf[0] != WLAN_EID_VENDOR_SPECIFIC)
		iebuf[1] = 0;
	if (iebuf[1] == 0 && ie.rsn_ie[1] > 0) {
		iebuf = ie.rsn_ie;
		if (iebuf[0] != WLAN_EID_RSN)
			iebuf[1] = 0;
	}
*/

	if ((iebuf[0] == WLAN_EID_VENDOR_SPECIFIC) || (iebuf[0] == WLAN_EID_RSN) )
	{
		piebuf = iebuf;
		ielen = iebuf[1];
		
		if (ielen == 0)
			piebuf = NULL;
		else
			ielen += 2;	
	}

no_ie:
	
	res = rtl871x_notif_assoc(hapd, addr, piebuf, ielen);

	if (memcmp(addr, drv->acct_mac, ETH_ALEN) == 0) {
		/* Cached accounting data is not valid anymore. */
		memset(drv->acct_mac, 0, ETH_ALEN);
		memset(&drv->acct_data, 0, sizeof(drv->acct_data));
	}

	return res;
	
}

static void rtl871x_wireless_event_wireless(struct rtl871x_driver_data *drv,
					    char *data, int len)
{
	struct iw_event iwe_buf, *iwe = &iwe_buf;
	char *pos, *end, *custom, *buf;

	pos = data;
	end = data + len;

	while (pos + IW_EV_LCP_LEN <= end) {
		/* Event data may be unaligned, so make a local, aligned copy
		 * before processing. */
		memcpy(&iwe_buf, pos, IW_EV_LCP_LEN);
		wpa_printf(MSG_MSGDUMP, "Wireless event: cmd=0x%x len=%d",
			   iwe->cmd, iwe->len);
		if (iwe->len <= IW_EV_LCP_LEN)
			return;

		custom = pos + IW_EV_POINT_LEN;
		if (drv->we_version > 18 &&
		    (iwe->cmd == IWEVMICHAELMICFAILURE ||
		     iwe->cmd == IWEVCUSTOM)) {
			/* WE-19 removed the pointer from struct iw_point */
			char *dpos = (char *) &iwe_buf.u.data.length;
			int dlen = dpos - (char *) &iwe_buf;
			memcpy(dpos, pos + IW_EV_LCP_LEN,
			       sizeof(struct iw_event) - dlen);
		} else {
			memcpy(&iwe_buf, pos, sizeof(struct iw_event));
			custom += IW_EV_POINT_OFF;
		}

		//printf("got wireless event, iwe->cmd=%d\n", iwe->cmd);

		switch (iwe->cmd) {
		case IWEVEXPIRED:
			rtl871x_del_sta(drv, (u8 *)iwe->u.addr.sa_data);
			break;
		case IWEVREGISTERED:
			if(rtl871x_new_sta(drv, (u8 *)iwe->u.addr.sa_data))
			{
				printf("Failed to add new sta: "MACSTR" \n", MAC2STR((u8 *)iwe->u.addr.sa_data));
			}
			break;
		case IWEVCUSTOM:
			if (custom + iwe->u.data.length > end)
				return;
			buf = malloc(iwe->u.data.length + 1);
			if (buf == NULL)
				return;		/* XXX */
			memcpy(buf, custom, iwe->u.data.length);
			buf[iwe->u.data.length] = '\0';
			//madwifi_wireless_event_wireless_custom(drv, buf);			
			free(buf);
			break;
		}

		pos += iwe->len;
	}
	
}

static void rtl871x_wireless_event_rtm_newlink(struct rtl871x_driver_data *drv,
					       struct nlmsghdr *h, int len)
{
	struct ifinfomsg *ifi;
	int attrlen, nlmsg_len, rta_len;
	struct rtattr * attr;

	if (len < (int) sizeof(*ifi))
		return;

	ifi = NLMSG_DATA(h);

	if (ifi->ifi_index != drv->ifindex)
		return;

	nlmsg_len = NLMSG_ALIGN(sizeof(struct ifinfomsg));

	attrlen = h->nlmsg_len - nlmsg_len;
	if (attrlen < 0)
		return;

	attr = (struct rtattr *) (((char *) ifi) + nlmsg_len);

	rta_len = RTA_ALIGN(sizeof(struct rtattr));
	while (RTA_OK(attr, attrlen)) {
		if (attr->rta_type == IFLA_WIRELESS) {
			rtl871x_wireless_event_wireless(
				drv, ((char *) attr) + rta_len,
				attr->rta_len - rta_len);
		} else if (attr->rta_type == IFLA_IFNAME) {
			//printf("IFLA_IFNAME: %s\n",((char *) attr) + rta_len);
		}
		attr = RTA_NEXT(attr, attrlen);
	}
}


static void rtl871x_wireless_event_receive(int sock, void *eloop_ctx, void *sock_ctx)
{
	char buf[256];//!!!
	int left;
	struct sockaddr_nl from;
	socklen_t fromlen;
	struct nlmsghdr *h;
	struct rtl871x_driver_data *drv = eloop_ctx;

	//printf("+rtl871x_wireless_event_receive\n");

	fromlen = sizeof(from);
	left = recvfrom(sock, buf, sizeof(buf), MSG_DONTWAIT,
			(struct sockaddr *) &from, &fromlen);
	if (left < 0) {
		if (errno != EINTR && errno != EAGAIN)
			perror("recvfrom(netlink)");
		return;
	}

	h = (struct nlmsghdr *)buf;
	while (left >= (int) sizeof(*h)) {
		int len, plen;

		len = h->nlmsg_len;
		plen = len - sizeof(*h);//payload len
		if (len > left || plen < 0) {
			printf("Malformed netlink message: "
			       "len=%d left=%d plen=%d\n",
			       len, left, plen);
			break;
		}

		switch (h->nlmsg_type) {
		case RTM_NEWLINK:
			rtl871x_wireless_event_rtm_newlink(drv, h, plen);
			break;
		}

		len = NLMSG_ALIGN(len);
		left -= len;
		h = (struct nlmsghdr *) ((char *) h + len);
	}

	if (left > 0) {
		printf("%d extra bytes in the end of netlink message\n", left);
	}
	
}

static int rtl871x_wireless_event_init_ops(void *priv)
{
	int s;
	struct sockaddr_nl local;
	struct rtl871x_driver_data *drv = priv;

	//madwifi_get_we_version(drv);

	drv->wext_sock = -1;

	s = socket(PF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
	if (s < 0) {
		perror("socket(PF_NETLINK,SOCK_RAW,NETLINK_ROUTE)");
		return -1;
	}

	memset(&local, 0, sizeof(local));
	local.nl_family = AF_NETLINK;
	local.nl_groups = RTMGRP_LINK;
	if (bind(s, (struct sockaddr *) &local, sizeof(local)) < 0) {
		perror("bind(netlink)");
		close(s);
		return -1;
	}

	eloop_register_read_sock(s, rtl871x_wireless_event_receive, drv, NULL);
	drv->wext_sock = s;

	return 0;
	
}

static void rtl871x_wireless_event_deinit_ops(void *priv)
{
	struct rtl871x_driver_data *drv = priv;

	if (drv != NULL) {
		if (drv->wext_sock < 0)
			return;
		eloop_unregister_read_sock(drv->wext_sock);
		close(drv->wext_sock);
	}
}

static void rtl871x_handle_read(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct rtl871x_driver_data *drv = ctx;
	struct hostapd_data *hapd = drv->hapd;
	struct sta_info *sta;

	sta = ap_get_sta(hapd, src_addr);
	if (!sta || !(sta->flags & WLAN_STA_ASSOC)) {
		printf("Data frame from not associated STA %s\n",
		       ether_sprintf(src_addr));
		/* XXX cannot happen */
		return;
	}
	ieee802_1x_receive(hapd, src_addr, buf + sizeof(struct l2_ethhdr),
			   len - sizeof(struct l2_ethhdr));
}

static int rtl871x_send_eapol_ops(void *priv, const u8 *addr, const u8 *data, size_t data_len,
		   int encrypt, const u8 *own_addr)
{
	struct rtl871x_driver_data *drv = priv;
	unsigned char buf[3000];
	unsigned char *bp = buf;
	struct l2_ethhdr *eth;
	size_t len;
	int status;

	printf("+rtl871x_send_eapol\n");

	/*
	 * Prepend the Ethernet header.  If the caller left us
	 * space at the front we could just insert it but since
	 * we don't know we copy to a local buffer.  Given the frequency
	 * and size of frames this probably doesn't matter.
	 */
	len = data_len + sizeof(struct l2_ethhdr);
	if (len > sizeof(buf)) {
		bp = malloc(len);
		if (bp == NULL) {
			printf("EAPOL frame discarded, cannot malloc temp "
			       "buffer of size %lu!\n", (unsigned long) len);
			return -1;
		}
	}
	
	eth = (struct l2_ethhdr *) bp;
	memcpy(eth->h_dest, addr, ETH_ALEN);
	memcpy(eth->h_source, own_addr, ETH_ALEN);
	eth->h_proto = htons(ETH_P_EAPOL);
	memcpy(eth+1, data, data_len);

	wpa_hexdump(MSG_MSGDUMP, "TX EAPOL", bp, len);

	status = l2_packet_send(drv->l2_sock, addr, ETH_P_EAPOL, bp, len);

	if (bp != buf)
		free(bp);
	
	return status;
	
}

static void rtl871x_receive_mgnt(struct rtl871x_driver_data *drv , const u8 *buf, size_t len)
{
	const struct ieee80211_mgmt *mgmt;
	//const u8 *end, *ie;
	u16 fc, type, stype;
	//size_t ie_len;
	struct hostapd_data *hapd = drv->hapd;

	//printf("+rtl871x_receive_mgnt, " MACSTR " is our address\n", MAC2STR(hapd->own_addr));

	
#if 0
	{
		int i;
		for(i=0; i<len; i+=8)
		{
			printf("%x:%x:%x:%x:%x:%x:%x:%x\n", buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7]);
		}	

	}
#endif

	if (len < IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req))
		return;

	mgmt = (const struct ieee80211_mgmt *)buf;

	fc = le_to_host16(mgmt->frame_control);
	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

#if 1
	if (WLAN_FC_GET_TYPE(fc) == WLAN_FC_TYPE_MGMT &&
	    WLAN_FC_GET_STYPE(fc) == WLAN_FC_STYPE_PROBE_RESP)
	{
		//printf("MGNT Frame - PROBE_RESP Frame\n");
	}
#endif

	//end = buf + len;
	//ie = mgmt->u.probe_req.variable;
	//ie_len = len - (IEEE80211_HDRLEN + sizeof(mgmt->u.probe_req));
	//hostapd_wps_probe_req_rx(drv->hapd, mgmt->sa, ie, ie_len);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		if (stype != WLAN_FC_STYPE_BEACON)
			wpa_printf(MSG_MSGDUMP, "MGMT");

		

		if (stype == WLAN_FC_STYPE_PROBE_REQ)
		{
		
		}
		else
		{
			//printf("rtl871x_receive_mgnt, type=0x%x, stype=0x%x\n", type, stype);
		}


		ieee802_11_mgmt(hapd, (u8 *)buf, len, stype, NULL);
		
		break;
	case WLAN_FC_TYPE_CTRL:
		printf("rtl871x_receive_mgnt, CTRL\n");
		break;
	case WLAN_FC_TYPE_DATA:
		printf("rtl871x_receive_mgnt, DATA\n");
		//handle_data(hapd, buf, data_len, stype);
		break;
	default:
		printf("unknown frame type %d\n", type);
		break;
	}

	
}

#ifdef CONFIG_MGNT_L2SOCK
static void rtl871x_recvive_mgmt_frame(void *ctx, const u8 *src_addr, const u8 *buf,
				size_t len)
{
	struct rtl871x_driver_data *drv = ctx;

	rtl871x_receive_mgnt(drv, buf, len);
}
#else
static void rtl871x_recvive_mgmt_frame(int sock, void *eloop_ctx, void *sock_ctx)
{	
	int len;
	unsigned char buf[1024];
	struct hostapd_data *hapd = (struct hostapd_data *)eloop_ctx;
	struct rtl871x_driver_data *drv = (struct rtl871x_driver_data *)hapd->drv_priv;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		perror("recv");
		return;
	}
	
	rtl871x_receive_mgnt(drv, buf, len);

}
static int rtl871x_mgnt_sock_init(struct rtl871x_driver_data *drv, const char *name)
{
	int sock;
	struct ifreq ifr;
	struct sockaddr_ll addr;

	sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (sock < 0) {
		perror("socket[PF_PACKET,SOCK_RAW]");
		return -1;
	}

	if (eloop_register_read_sock(sock, rtl871x_recvive_mgmt_frame, drv->hapd, NULL))
	{
		printf("Could not register read socket\n");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	//snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%sap", drv->iface);
	os_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
        if (ioctl(sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		return -1;
        }

	//if (rtl871x_set_iface_flags(drv, 1)) {
	//	return -1;
	//}

	memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
		perror("bind");
		return -1;
	}

        memset(&ifr, 0, sizeof(ifr));
        os_strlcpy(ifr.ifr_name, name, sizeof(ifr.ifr_name));
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) != 0) {
		perror("ioctl(SIOCGIFHWADDR)");
		return -1;
        }


	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		printf("Invalid HW-addr family 0x%04x\n",
		       ifr.ifr_hwaddr.sa_family);
		return -1;
	}
	
	//memcpy(drv->hapd->own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	return sock;
	
}
#endif

static void rtl871x_handle_tx_callback(struct hostapd_data *hapd, u8 *buf, size_t len,
			       int ok)
{
	struct ieee80211_hdr *hdr;
	u16 fc, type, stype;
	struct sta_info *sta;

	//printf("%s\n", __func__);

	hdr = (struct ieee80211_hdr *) buf;
	fc = le_to_host16(hdr->frame_control);

	type = WLAN_FC_GET_TYPE(fc);
	stype = WLAN_FC_GET_STYPE(fc);

	switch (type) {
	case WLAN_FC_TYPE_MGMT:
		//printf("MGMT (TX callback) %s\n",
		//	   ok ? "ACK" : "fail");
		ieee802_11_mgmt_cb(hapd, buf, len, stype, ok);
		break;
	case WLAN_FC_TYPE_CTRL:
		printf("CTRL (TX callback) %s\n",
			   ok ? "ACK" : "fail");
		break;
	case WLAN_FC_TYPE_DATA:
		printf("DATA (TX callback) %s\n",
			   ok ? "ACK" : "fail");
		sta = ap_get_sta(hapd, hdr->addr1);
		if (sta && sta->flags & WLAN_STA_PENDING_POLL) {
			wpa_printf(MSG_DEBUG, "STA " MACSTR
				   " %s pending activity poll",
				   MAC2STR(sta->addr),
				   ok ? "ACKed" : "did not ACK");
			if (ok)
				sta->flags &= ~WLAN_STA_PENDING_POLL;
		}
		if (sta)
			ieee802_1x_tx_status(hapd, sta, buf, len, ok);
		break;
	default:
		printf("unknown TX callback frame type %d\n", type);
		break;
	}
	
}	

static int rtl871x_send_mgnt(struct rtl871x_driver_data *drv, const void *msg, size_t len)
{
	int res=0;

	return res;
}

static int rtl871x_send_mgmt_frame_ops(void *priv, const void *msg, size_t len,
				  int flags)
{
	struct rtl871x_driver_data *drv = priv;
	//struct ieee80211_hdr *hdr = (struct ieee80211_hdr *)msg;
	int res;

	//printf("%s\n", __func__);

	
	//hdr->frame_control |= host_to_le16(BIT(1));/* Request TX callback */
#ifdef CONFIG_MGNT_L2SOCK
	//res = send(drv->mgnt_l2_sock, msg, len, flags);
	//res = l2_packet_send(drv->mgnt_l2_sock, addr, ETH_P_EAPOL, msg, len);
	res = l2_packet_send(drv->mgnt_l2_sock, NULL, ETH_P_80211_RAW, msg, len);
#else
	res = send(drv->mgnt_sock, msg, len, flags);
#endif
	//hdr->frame_control &= ~host_to_le16(BIT(1));
	

	rtl871x_send_mgnt(drv, msg, len);

	rtl871x_handle_tx_callback(drv->hapd, (u8*)msg, len, 1);

	return res;
	
}

static int rtl871x_driver_send_ether_ops(void *priv, const u8 *dst, const u8 *src,
				  u16 proto, const u8 *data, size_t data_len)
{
	return 0;
}

#if 1 // support 5G
static struct hostapd_hw_modes *rtl871x_get_hw_feature_data_ops(void *priv,
							    u16 *num_modes,
							    u16 *flags)
{
	struct hostapd_hw_modes *modes;
	int i, clen, rlen;
	int ch_idx = 0;
	const short chan2freq_24G[14] = {
		2412, 2417, 2422, 2427, 2432, 2437, 2442,
		2447, 2452, 2457, 2462, 2467, 2472, 2484
	};

	*num_modes = 2;
	*flags = 0;
	modes = os_zalloc(*num_modes * sizeof(struct hostapd_hw_modes));
	if (modes == NULL)
		return NULL;
		
	modes[0].mode = HOSTAPD_MODE_IEEE80211G;
	modes[0].num_channels = 14;
	modes[0].num_rates = 12;

	clen = modes[0].num_channels * sizeof(struct hostapd_channel_data);
	rlen = modes[0].num_rates * sizeof(struct hostapd_rate_data);

	modes[0].channels = os_zalloc(clen);
	modes[0].rates = os_zalloc(rlen);
	if (modes[0].channels == NULL || modes[0].rates == NULL) {
		hostapd_free_hw_features(modes, *num_modes);
		return NULL;
	}

	for (i = 0; i < 14; i++) {
		modes[0].channels[i].chan = i + 1;
		modes[0].channels[i].freq = chan2freq_24G[i];
		/* TODO: Get allowed channel list from the driver */
		if (i >= 11)
			modes[0].channels[i].flag = HOSTAPD_CHAN_DISABLED;
	}

	modes[0].rates[0].rate = 10;
	modes[0].rates[0].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;
	modes[0].rates[1].rate = 20;
	modes[0].rates[1].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;
	modes[0].rates[2].rate = 55;
	modes[0].rates[2].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;
	modes[0].rates[3].rate = 110;
	modes[0].rates[3].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;

	modes[0].rates[4].rate = 60;
	modes[0].rates[4].flags = HOSTAPD_RATE_OFDM;
	modes[0].rates[5].rate = 90;
	modes[0].rates[5].flags = HOSTAPD_RATE_OFDM;
	modes[0].rates[6].rate = 120;
	modes[0].rates[6].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[0].rates[7].rate = 180;
	modes[0].rates[7].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;


	modes[0].rates[8].rate = 240;
	modes[0].rates[8].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[0].rates[9].rate = 360;
	modes[0].rates[9].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[0].rates[10].rate = 480;
	modes[0].rates[10].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[0].rates[11].rate = 540;
	modes[0].rates[11].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[0].ht_capab = HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET|HT_CAP_INFO_SHORT_GI20MHZ|
			HT_CAP_INFO_SHORT_GI40MHZ|HT_CAP_INFO_MAX_AMSDU_SIZE|HT_CAP_INFO_DSSS_CCK40MHZ;


/*
	modes[1].mode = HOSTAPD_MODE_IEEE80211B;
	modes[1].num_channels = 1;
	modes[1].num_rates = 1;
	modes[1].channels = os_zalloc(sizeof(struct hostapd_channel_data));
	modes[1].rates = os_zalloc(sizeof(struct hostapd_rate_data));
	if (modes[1].channels == NULL || modes[1].rates == NULL) {
		hostapd_free_hw_features(modes, *num_modes);
		return NULL;
	}
	modes[1].channels[0].chan = 1;
	modes[1].channels[0].freq = 2412;
	modes[1].channels[0].flag = 0;
	modes[1].rates[0].rate = 10;
	modes[1].rates[0].flags = HOSTAPD_RATE_BASIC | HOSTAPD_RATE_SUPPORTED |
		HOSTAPD_RATE_CCK | HOSTAPD_RATE_MANDATORY;
*/

	
	modes[1].mode = HOSTAPD_MODE_IEEE80211A;
#ifdef CONFIG_DRIVER_RTL_DFS
	modes[1].num_channels = 24;
#else /* CONFIG_DRIVER_RTL_DFS */
	modes[1].num_channels = 9;
#endif /* CONFIG_DRIVER_RTL_DFS */

	modes[1].num_rates = 8;
	modes[1].channels = os_zalloc(modes[1].num_channels * sizeof(struct hostapd_channel_data));
	modes[1].rates = os_zalloc(modes[1].num_rates * sizeof(struct hostapd_rate_data));
	if (modes[1].channels == NULL || modes[1].rates == NULL) {
		hostapd_free_hw_features(modes, *num_modes);
		return NULL;
	}

	// 5G band1 Channel: 36, 40, 44, 48
	for (i=0; i < 4; i++) {
		modes[1].channels[ch_idx].chan = 36+(i*4);
		modes[1].channels[ch_idx].freq = 5180+(i*20);
		modes[1].channels[ch_idx].flag = 0;
		ch_idx++;
	}

#ifdef CONFIG_DRIVER_RTL_DFS
	// 5G band2 Channel: 52, 56, 60, 64
	for (i=0; i < 4; i++) {
		modes[1].channels[ch_idx].chan = 52+(i*4);
		modes[1].channels[ch_idx].freq = 5260+(i*20);
		modes[1].channels[ch_idx].flag = 0;
		ch_idx++;
	}

	// 5G band3 Channel: 100, 104, 108. 112, 116, 120, 124, 128, 132, 136, 140
	for (i=0; i < 11; i++) {
		modes[1].channels[ch_idx].chan = 100+(i*4);
		modes[1].channels[ch_idx].freq = 5500+(i*20);
		modes[1].channels[ch_idx].flag = 0;
		ch_idx++;
	}
#endif /* CONFIG_DRIVER_RTL_DFS */

	// 5G band4 Channel: 149, 153, 157, 161, 165
	for (i=0; i < 5; i++) {
		modes[1].channels[ch_idx].chan = 149+(i*4);
		modes[1].channels[ch_idx].freq = 5745+(i*20);
		modes[1].channels[ch_idx].flag = 0;
		ch_idx++;
	}

	// 5G can't support CCK rate
	modes[1].rates[0].rate = 60;
	modes[1].rates[0].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[1].rates[1].rate = 90;
	modes[1].rates[1].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[1].rates[2].rate = 120;
	modes[1].rates[2].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[1].rates[3].rate = 180;
	modes[1].rates[3].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;


	modes[1].rates[4].rate = 240;
	modes[1].rates[4].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[1].rates[5].rate = 360;
	modes[1].rates[5].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[1].rates[6].rate = 480;
	modes[1].rates[6].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	modes[1].rates[7].rate = 540;
	modes[1].rates[7].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;

	modes[1].ht_capab = HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET|HT_CAP_INFO_SHORT_GI20MHZ|
			HT_CAP_INFO_SHORT_GI40MHZ|HT_CAP_INFO_MAX_AMSDU_SIZE|HT_CAP_INFO_DSSS_CCK40MHZ;

	return modes;
}

#else // support 5G

static struct hostapd_hw_modes *rtl871x_get_hw_feature_data_ops(void *priv,
							    u16 *num_modes,
							    u16 *flags)
{
	struct hostapd_hw_modes *mode;
	int i, clen, rlen;
	const short chan2freq[14] = {
		2412, 2417, 2422, 2427, 2432, 2437, 2442,
		2447, 2452, 2457, 2462, 2467, 2472, 2484
	};

	mode = os_zalloc(sizeof(struct hostapd_hw_modes));
	if (mode == NULL)
		return NULL;

	*num_modes = 1;
	*flags = 0;

	mode->mode = HOSTAPD_MODE_IEEE80211G;
	mode->num_channels = 14;
	mode->num_rates = 12;

	clen = mode->num_channels * sizeof(struct hostapd_channel_data);
	rlen = mode->num_rates * sizeof(struct hostapd_rate_data);

	mode->channels = os_zalloc(clen);
	mode->rates = os_zalloc(rlen);
	if (mode->channels == NULL || mode->rates == NULL) {
		hostapd_free_hw_features(mode, *num_modes);
		return NULL;
	}

	for (i = 0; i < 14; i++) {
		mode->channels[i].chan = i + 1;
		mode->channels[i].freq = chan2freq[i];
		/* TODO: Get allowed channel list from the driver */
		if (i >= 11)
			mode->channels[i].flag = HOSTAPD_CHAN_DISABLED;
	}

	mode->rates[0].rate = 10;
	mode->rates[0].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;
	mode->rates[1].rate = 20;
	mode->rates[1].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;
	mode->rates[2].rate = 55;
	mode->rates[2].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;
	mode->rates[3].rate = 110;
	mode->rates[3].flags = HOSTAPD_RATE_CCK | HOSTAPD_RATE_BASIC;

	mode->rates[4].rate = 60;
	mode->rates[4].flags = HOSTAPD_RATE_OFDM;
	mode->rates[5].rate = 90;
	mode->rates[5].flags = HOSTAPD_RATE_OFDM;
	mode->rates[6].rate = 120;
	mode->rates[6].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	mode->rates[7].rate = 180;
	mode->rates[7].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;


	mode->rates[8].rate = 240;
	mode->rates[8].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	mode->rates[9].rate = 360;
	mode->rates[9].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	mode->rates[10].rate = 480;
	mode->rates[10].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;
	mode->rates[11].rate = 540;
	mode->rates[11].flags = HOSTAPD_RATE_OFDM | HOSTAPD_RATE_BASIC;



	//
#if 0	
#define HT_CAP_INFO_LDPC_CODING_CAP		((u16) BIT(0))
#define HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET	((u16) BIT(1))
#define HT_CAP_INFO_SMPS_MASK			((u16) (BIT(2) | BIT(3)))
#define HT_CAP_INFO_SMPS_STATIC			((u16) 0)
#define HT_CAP_INFO_SMPS_DYNAMIC		((u16) BIT(2))
#define HT_CAP_INFO_SMPS_DISABLED		((u16) (BIT(2) | BIT(3)))
#define HT_CAP_INFO_GREEN_FIELD			((u16) BIT(4))
#define HT_CAP_INFO_SHORT_GI20MHZ		((u16) BIT(5))
#define HT_CAP_INFO_SHORT_GI40MHZ		((u16) BIT(6))
#define HT_CAP_INFO_TX_STBC			((u16) BIT(7))
#define HT_CAP_INFO_RX_STBC_MASK		((u16) (BIT(8) | BIT(9)))
#define HT_CAP_INFO_RX_STBC_1			((u16) BIT(8))
#define HT_CAP_INFO_RX_STBC_12			((u16) BIT(9))
#define HT_CAP_INFO_RX_STBC_123			((u16) (BIT(8) | BIT(9)))
#define HT_CAP_INFO_DELAYED_BA			((u16) BIT(10))
#define HT_CAP_INFO_MAX_AMSDU_SIZE		((u16) BIT(11))
#define HT_CAP_INFO_DSSS_CCK40MHZ		((u16) BIT(12))
#define HT_CAP_INFO_PSMP_SUPP			((u16) BIT(13))
#define HT_CAP_INFO_40MHZ_INTOLERANT		((u16) BIT(14))
#define HT_CAP_INFO_LSIG_TXOP_PROTECT_SUPPORT	((u16) BIT(15))
#endif

	mode->ht_capab = HT_CAP_INFO_SUPP_CHANNEL_WIDTH_SET|HT_CAP_INFO_SHORT_GI20MHZ|
			HT_CAP_INFO_SHORT_GI40MHZ|HT_CAP_INFO_MAX_AMSDU_SIZE|HT_CAP_INFO_DSSS_CCK40MHZ;
	

	return mode;
	
}
#endif // support 5G

static int rtl871x_sta_add_ops(const char *ifname, void *priv, const u8 *addr,
			  u16 aid, u16 capability, u8 *supp_rates,
			  size_t supp_rates_len, int flags,
			  u16 listen_interval)
{

#if 1
	printf("+%s, " MACSTR " is new sta address added\n", __func__, MAC2STR(addr));
	return 0;
#else	
	struct hostap_driver_data *drv = priv;
	struct prism2_hostapd_param param;
	int tx_supp_rates = 0;
	size_t i;

#define WLAN_RATE_1M BIT(0)
#define WLAN_RATE_2M BIT(1)
#define WLAN_RATE_5M5 BIT(2)
#define WLAN_RATE_11M BIT(3)

	for (i = 0; i < supp_rates_len; i++) {
		if ((supp_rates[i] & 0x7f) == 2)
			tx_supp_rates |= WLAN_RATE_1M;
		if ((supp_rates[i] & 0x7f) == 4)
			tx_supp_rates |= WLAN_RATE_2M;
		if ((supp_rates[i] & 0x7f) == 11)
			tx_supp_rates |= WLAN_RATE_5M5;
		if ((supp_rates[i] & 0x7f) == 22)
			tx_supp_rates |= WLAN_RATE_11M;
	}

	memset(&param, 0, sizeof(param));
	param.cmd = PRISM2_HOSTAPD_ADD_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	param.u.add_sta.aid = aid;
	param.u.add_sta.capability = capability;
	param.u.add_sta.tx_supp_rates = tx_supp_rates;
	return hostapd_ioctl(drv, &param, sizeof(param));
#endif	
}

static int rtl871x_sta_add2_ops(const char *ifname, void *priv,
			 struct hostapd_sta_add_params *params)
{
	
#if 1
	ieee_param param;
	//int i, tx_supp_rates = 0;
	struct rtl871x_driver_data *drv = priv;
	
	printf("%s\n", __func__);

	memset(&param, 0, sizeof(param));
	param.cmd = RTL871X_HOSTAPD_ADD_STA;
	memcpy(param.sta_addr, params->addr, ETH_ALEN);
	param.u.add_sta.aid = params->aid;
	param.u.add_sta.capability = params->capability;
	param.u.add_sta.flags = params->flags;

	memcpy(param.u.add_sta.tx_supp_rates, params->supp_rates, params->supp_rates_len);

/*	
	for (i = 0; i < params->supp_rates_len; i++)
	{		
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_CCK_RATE_1MB)
			tx_supp_rates |= IEEE80211_CCK_RATE_1MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_CCK_RATE_2MB)
			tx_supp_rates |= IEEE80211_CCK_RATE_2MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_CCK_RATE_5MB)
			tx_supp_rates |= IEEE80211_CCK_RATE_5MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_CCK_RATE_11MB)
			tx_supp_rates |= IEEE80211_CCK_RATE_11MB_MASK;

		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_6MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_6MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_9MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_9MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_12MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_12MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_18MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_18MB_MASK;

		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_24MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_24MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_36MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_36MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_48MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_48MB_MASK;
		if ((params->supp_rates[i] & 0x7f) == IEEE80211_OFDM_RATE_54MB)
			tx_supp_rates |= IEEE80211_OFDM_RATE_54MB_MASK;
		
	}

	param.u.add_sta.tx_supp_rates = tx_supp_rates;
*/	
	
#ifdef CONFIG_IEEE80211N
	if (params->ht_capabilities && params->ht_capabilities->length>0) 
	{
		struct ieee80211_ht_capability *pht_cap = (struct ieee80211_ht_capability *)&params->ht_capabilities->data;
		memcpy((u8*)&param.u.add_sta.ht_cap, (u8*)pht_cap, sizeof(struct ieee80211_ht_capability));
		
	}
#endif /* CONFIG_IEEE80211N */
	
	return rtl871x_hostapd_ioctl(drv, &param, sizeof(param));

#else
	struct i802_driver_data *drv = priv;
	struct nl_msg *msg;
	int ret = -ENOBUFS;

	msg = nlmsg_alloc();
	if (!msg)
		return -ENOMEM;

	genlmsg_put(msg, 0, 0, genl_family_get_id(drv->nl80211), 0,
		    0, NL80211_CMD_NEW_STATION, 0);

	NLA_PUT_U32(msg, NL80211_ATTR_IFINDEX,
		    if_nametoindex(drv->iface));
	NLA_PUT(msg, NL80211_ATTR_MAC, ETH_ALEN, params->addr);
	NLA_PUT_U16(msg, NL80211_ATTR_STA_AID, params->aid);
	NLA_PUT(msg, NL80211_ATTR_STA_SUPPORTED_RATES, params->supp_rates_len,
		params->supp_rates);
	NLA_PUT_U16(msg, NL80211_ATTR_STA_LISTEN_INTERVAL,
		    params->listen_interval);

#ifdef CONFIG_IEEE80211N
	if (params->ht_capabilities) {
		NLA_PUT(msg, NL80211_ATTR_HT_CAPABILITY,
			params->ht_capabilities->length,
			&params->ht_capabilities->data);
	}
#endif /* CONFIG_IEEE80211N */

	ret = send_and_recv_msgs(drv, msg, NULL, NULL);
	if (ret)
		wpa_printf(MSG_DEBUG, "nl80211: NL80211_CMD_NEW_STATION "
			   "result: %d (%s)", ret, strerror(-ret));
	if (ret == -EEXIST)
		ret = 0;
 nla_put_failure:
	return ret;
#endif	
}


static int rtl871x_sta_remove_ops(void *priv, const u8 *addr)
{
	struct rtl871x_driver_data *drv = priv;
	struct ieee_param param;

	printf("+%s, " MACSTR " is sta address removed\n", __func__, MAC2STR(addr));

	//hostap_sta_set_flags(drv, addr, 0, 0, ~WLAN_STA_AUTHORIZED);

	memset(&param, 0, sizeof(param));
	param.cmd = RTL871X_HOSTAPD_REMOVE_STA;
	memcpy(param.sta_addr, addr, ETH_ALEN);
	if (rtl871x_hostapd_ioctl(drv, &param, sizeof(param))) {
		printf("Could not remove station from kernel driver.\n");
		return -1;
	}
	
	return 0;	

}

static int rtl871x_set_beacon_ops(const char *iface, void *priv,
			   u8 *head, size_t head_len,
			   u8 *tail, size_t tail_len)
{
	int ret;
	size_t sz;
	ieee_param *pparam;
	struct rtl871x_driver_data *drv = priv;
	struct hostapd_data *hapd = drv->hapd;
	
	if((head_len<24) ||(!head))
		return -1;

	printf("%s\n", __func__);

	sz = head_len+tail_len+12-24 + 2;// 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_BEACON;

	memcpy(pparam->u.bcn_ie.reserved, &hapd->conf->max_num_sta, 2);//for set max_num_sta

	memcpy(pparam->u.bcn_ie.buf, (head+24), (head_len-24));// 24=beacon header len.
	
	memcpy(&pparam->u.bcn_ie.buf[head_len-24], tail, tail_len);
	
	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);

	os_free(pparam);

	//rtl871x_set_max_num_sta(drv);
	
	return ret;
	
}

static int rtl871x_set_encryption_ops(const char *ifname, void *priv,
				 const char *alg, const u8 *addr,
				 int idx, const u8 *key, size_t key_len,
				 int txkey)
{
	ieee_param *param;	
	u8 *buf;
	size_t blen;
	int ret = 0;
	struct rtl871x_driver_data *drv = priv;

	printf("%s\n", __func__);

	blen = sizeof(*param) + key_len;
	buf = os_zalloc(blen);
	if (buf == NULL)
		return -1;

	param = (ieee_param *)buf;
	param->cmd = RTL871X_SET_ENCRYPTION;
	if (addr == NULL)
		memset(param->sta_addr, 0xff, ETH_ALEN);
	else
		memcpy(param->sta_addr, addr, ETH_ALEN);
	
	os_strlcpy((char *) param->u.crypt.alg, alg,
		   IEEE_CRYPT_ALG_NAME_LEN);
	
	//param->u.crypt.flags = txkey ? HOSTAP_CRYPT_FLAG_SET_TX_KEY : 0;
	param->u.crypt.set_tx = txkey ? 1 : 0;
	param->u.crypt.idx = idx;
	param->u.crypt.key_len = key_len;
	
	//memcpy((u8 *) (param + 1), key, key_len);
	memcpy(param->u.crypt.key, key, key_len);

	if (rtl871x_hostapd_ioctl(drv, param, blen)) {
		printf("Failed to set encryption.\n");
		ret = -1;
	}
	
	os_free(buf);

	return ret;
	
}

static int rtl871x_sta_deauth_ops(void *priv, const u8 *addr, int reason)
{
	printf("+%s, " MACSTR " is deauth, reason=%d\n", __func__, MAC2STR(addr), reason);

	//struct hostap_driver_data *drv = priv;
	struct rtl871x_driver_data *drv = priv;
	struct ieee80211_mgmt mgmt;

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_DEAUTH);
	
	memcpy(mgmt.da, addr, ETH_ALEN);
	memcpy(mgmt.sa, drv->hapd->own_addr, ETH_ALEN);
	memcpy(mgmt.bssid, drv->hapd->own_addr, ETH_ALEN);
	mgmt.u.deauth.reason_code = host_to_le16(reason);

	return rtl871x_send_mgmt_frame_ops(drv, &mgmt, IEEE80211_HDRLEN +
				      sizeof(mgmt.u.deauth), 0);
	
}


static int rtl871x_sta_disassoc_ops(void *priv, const u8 *addr, int reason)
{
	printf("+%s, " MACSTR " is disassoc, reason=%d\n", __func__, MAC2STR(addr), reason);

	struct rtl871x_driver_data *drv = priv;
	struct ieee80211_mgmt mgmt;

	memset(&mgmt, 0, sizeof(mgmt));
	mgmt.frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					  WLAN_FC_STYPE_DISASSOC);
	
	memcpy(mgmt.da, addr, ETH_ALEN);
	memcpy(mgmt.sa, drv->hapd->own_addr, ETH_ALEN);
	memcpy(mgmt.bssid, drv->hapd->own_addr, ETH_ALEN);
	
	mgmt.u.disassoc.reason_code = host_to_le16(reason);
	
	return  rtl871x_send_mgmt_frame_ops(drv, &mgmt, IEEE80211_HDRLEN +
				       sizeof(mgmt.u.disassoc), 0);

}

static int rtl871x_set_wps_beacon_ie_ops(const char *ifname, void *priv, const u8 *ie,
			  size_t len)
{
	int ret;
	size_t sz;
	ieee_param *pparam;
	struct rtl871x_driver_data *drv = priv;
	
	printf("%s\n", __func__);

	sz = len + 12 + 2;// 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_WPS_BEACON;	
		
	if(ie && len>0)
	{
		memcpy(pparam->u.bcn_ie.buf, ie, len);
	}

	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);

	os_free(pparam);

	return ret;
	
}

static int rtl871x_set_wps_probe_resp_ie_ops(const char *ifname, void *priv, const u8 *ie,
			  size_t len)
{
	int ret;
	size_t sz;
	ieee_param *pparam;
	struct rtl871x_driver_data *drv = priv;
	
	printf("%s\n", __func__);

	sz = len + 12 + 2;// 12+2 = cmd+sta_addr+reserved, sizeof(ieee_param)=64, no packed
	pparam = os_zalloc(sz);
	if (pparam == NULL) {
		return -ENOMEM;
	}

	pparam->cmd = RTL871X_HOSTAPD_SET_WPS_PROBE_RESP;	
		
	if(ie && len>0)
	{
		memcpy(pparam->u.bcn_ie.buf, ie, len);
	}

	ret = rtl871x_hostapd_ioctl(drv, pparam, sz);

	os_free(pparam);

	return ret;
	
}			   

static int rtl871x_sta_flush_ops(void *priv)
{
	ieee_param param;
	struct rtl871x_driver_data *drv = priv;	

	memset(&param, 0, sizeof(param));
	
	param.cmd = RTL871X_HOSTAPD_FLUSH;	
	
	return rtl871x_hostapd_ioctl(drv, &param, sizeof(param));
}

static void *rtl871x_driver_init_ops(struct hostapd_data *hapd)
{
	struct rtl871x_driver_data *drv;
	struct ifreq ifr;
	struct iwreq iwr;
	char	ifrn_name[IFNAMSIZ + 1];//for mgnt_l2_sock/mgnt_sock

	drv = os_zalloc(sizeof(struct rtl871x_driver_data));
	if (drv == NULL) {
		printf("Could not allocate memory for rtl871x driver data\n");
		return NULL;
	}

	drv->hapd = hapd;
	drv->ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (drv->ioctl_sock < 0) {
		perror("socket[PF_INET,SOCK_DGRAM]");
		goto bad;
	}
	memcpy(drv->iface, hapd->conf->iface, sizeof(drv->iface));

	rtl871x_set_iface_flags(drv, 1, 0);	/*set interface up*/
	rtl871x_drv_set_pid_fd(
		drv->ioctl_sock
		, drv->iface
		, 1
		, getppid()
	);
	
	
	memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->iface, sizeof(ifr.ifr_name));
	if (ioctl(drv->ioctl_sock, SIOCGIFINDEX, &ifr) != 0) {
		perror("ioctl(SIOCGIFINDEX)");
		goto bad;
	}
	drv->ifindex = ifr.ifr_ifindex;
	printf("drv->ifindex=%d\n", drv->ifindex);

	drv->l2_sock = l2_packet_init(drv->iface, NULL, ETH_P_EAPOL,
					rtl871x_handle_read, drv, 1);

	if (drv->l2_sock == NULL)
		goto bad;

	if (l2_packet_get_own_addr(drv->l2_sock, hapd->own_addr))
		goto bad;

	if (hapd->conf->bridge[0] != '\0') {
		wpa_printf(MSG_DEBUG, "Configure bridge %s for EAPOL traffic.",
			   hapd->conf->bridge);
#if 1		
		drv->l2_sock_recv = l2_packet_init(hapd->conf->bridge, NULL,
						ETH_P_EAPOL, rtl871x_handle_read, drv,
						1);
		if (drv->l2_sock_recv == NULL)
		{
			//goto bad;
			drv->l2_sock_recv = drv->l2_sock;
			printf("no br0 interface , let l2_sock_recv==l2_sock_xmit=0x%p\n", drv->l2_sock);	
		}	
#endif		
	}
	else
	{
		drv->l2_sock_recv = drv->l2_sock;
		printf("l2_sock_recv==l2_sock_xmit=0x%p\n", drv->l2_sock);	
	}



	memset(ifrn_name, 0, sizeof(ifrn_name));
	//snprintf(ifrn_name, sizeof(ifrn_name), "mgnt.%s_rena", drv->iface);
	snprintf(ifrn_name, sizeof(ifrn_name), "mgnt.%s", "wlan0"/*drv->iface*/);
	

#ifdef CONFIG_MGNT_L2SOCK	
	drv->mgnt_l2_sock = NULL;
	drv->mgnt_l2_sock = l2_packet_init(ifrn_name, NULL, ETH_P_80211_RAW,
				       rtl871x_recvive_mgmt_frame, drv, 1);
	if (drv->mgnt_l2_sock == NULL)
		goto bad;
	
#else

#ifdef CONFIG_MLME_OFFLOAD
	drv->mgnt_sock = -1;
#else
	drv->mgnt_sock = rtl871x_mgnt_sock_init(drv, ifrn_name);
	if (drv->mgnt_sock < 0) {		
		goto bad;
	}
#endif

#endif
	


	//madwifi_set_iface_flags(drv, 0);	/* mark down during setup */
	//madwifi_set_privacy(drv->iface, drv, 0); /* default to no privacy */

	//enter MASTER MODE when init.
	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.mode = IW_MODE_MASTER;
	if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) < 0) {
		perror("ioctl[SIOCSIWMODE]");
		printf("Could not set interface to master mode!\n");
		goto bad;
	}

	rtl871x_set_iface_flags(drv, 1, 1);	/*set mgnt interface up*/

	return drv;
	
bad:
	
	if (drv->l2_sock_recv != NULL && drv->l2_sock_recv != drv->l2_sock)
		l2_packet_deinit(drv->l2_sock_recv);
	
	if (drv->l2_sock != NULL)
		l2_packet_deinit(drv->l2_sock);
	
	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);

#ifdef CONFIG_MGNT_L2SOCK
	if ( drv->mgnt_l2_sock != NULL)
		l2_packet_deinit(drv->mgnt_l2_sock);
#else
	if (drv->mgnt_sock >= 0)
		close(drv->mgnt_sock);
#endif
	
	if (drv != NULL)
		free(drv);
	
	return NULL;
	
}

static void rtl871x_driver_deinit_ops(void *priv)
{
	struct iwreq iwr;
	struct rtl871x_driver_data *drv = priv;

	//back to INFRA MODE when exit.
	memset(&iwr, 0, sizeof(iwr));
	os_strlcpy(iwr.ifr_name, drv->iface, IFNAMSIZ);
	iwr.u.mode = IW_MODE_INFRA;
	if (ioctl(drv->ioctl_sock, SIOCSIWMODE, &iwr) < 0) {
		perror("ioctl[SIOCSIWMODE]");
	}
 
	rtl871x_drv_set_pid_fd(
		drv->ioctl_sock
		, drv->iface
		, 1
		, 0
	);


	if (drv->ioctl_sock >= 0)
		close(drv->ioctl_sock);

	
	if (drv->l2_sock_recv != NULL && drv->l2_sock_recv != drv->l2_sock)
		l2_packet_deinit(drv->l2_sock_recv);

	if(drv->l2_sock)
		l2_packet_deinit(drv->l2_sock);	

	//if (drv->sock_xmit != NULL)
	//	l2_packet_deinit(drv->sock_xmit);

#ifdef CONFIG_MGNT_L2SOCK	
	if (drv->mgnt_l2_sock)
		l2_packet_deinit(drv->mgnt_l2_sock);
#else
	if (drv->mgnt_sock >= 0)
		close(drv->mgnt_sock);
#endif

	os_free(drv);
	
}


const struct wpa_driver_ops wpa_driver_rtl_ops = {
	.name = "rtl871xdrv",
	.init = rtl871x_driver_init_ops,
	.deinit = rtl871x_driver_deinit_ops,
	.wireless_event_init	= rtl871x_wireless_event_init_ops,
	.wireless_event_deinit	= rtl871x_wireless_event_deinit_ops,
	.send_eapol		= rtl871x_send_eapol_ops,
	.send_ether = rtl871x_driver_send_ether_ops,
	.send_mgmt_frame = rtl871x_send_mgmt_frame_ops,
	.get_hw_feature_data = rtl871x_get_hw_feature_data_ops,
	.sta_add = rtl871x_sta_add_ops,
	.sta_add2 = rtl871x_sta_add2_ops,
	.sta_remove = rtl871x_sta_remove_ops,
	.set_beacon = rtl871x_set_beacon_ops,
	.set_encryption = rtl871x_set_encryption_ops,
	.sta_deauth = rtl871x_sta_deauth_ops,
	.sta_disassoc = rtl871x_sta_disassoc_ops,
	.set_wps_beacon_ie = rtl871x_set_wps_beacon_ie_ops,
	.set_wps_probe_resp_ie = rtl871x_set_wps_probe_resp_ie_ops,	
	.flush			= rtl871x_sta_flush_ops,
};

