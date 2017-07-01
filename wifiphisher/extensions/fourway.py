"""
Extension that capture the four way handshake and
do the verification whether the password given by
-pK option is valid
"""

import binascii
import hmac
import hashlib
from collections import deque
from pbkdf2 import PBKDF2
import scapy.layers.dot11 as dot11
import wifiphisher.common.constants as constants


class Fourway(object):
    """
    Handles four way handshake verification
    """

    def __init__(self, data):
        """
        Setup the class with all the given arguments.

        :param self: A Fourway object.
        :param data: Shared data from main engine
        :type self: Fourway
        :type data: dictionary
        :return: None
        :rtype: None
        """

        # store the fourway eapols to calculate
        self._eapols = deque()
        self._data = data
        # check if the verification is done
        self._is_done = False
        # check if the fourway handshake is captured
        self._is_captured = False
        # check if the capture given by user is processed
        self._is_first = True

    @staticmethod
    def _is_retried_frame(packet):
        """
        Detect if the frame is retried frame
        :param packet: A scapy.layers.RadioTap object
        :type self: Fourway
        :return True if this frame is a retried frame
        :rtype: bool
        ..note: we want to skip the retried frames for the fourway handshake
        verification
        """

        # Retried field is BIT3 in the frame control field
        is_retried = True if packet.FCfield & (1 << 3) else False
        return is_retried

    @staticmethod
    def _prf512(key, const_a, const_b):
        """
        Calculate the PTK from the PMK
        :param key: PMK
        :param const_a: Constant defined in 802.11
        :param const_b: Constant define in 802.11
        :type key: str
        :type const_a: str
        :type const_b: str
        :return: PTK
        :rtype: str
        """

        blen = 64
        index = 0
        return_array = ''
        while index <= ((blen * 8 + 159) / 160):
            hmacsha1 = hmac.new(key, const_a + chr(0x00) + const_b +
                                chr(index), hashlib.sha1)
            index += 1
            return_array = return_array + hmacsha1.digest()
        return return_array[:blen]

    def _verify_creds(self):
        """
        Verify the passphrase given by users is corrected
        :param packet: A scapy.layers.RadioTap object
        :type self: Fourway
        :return True if verifcation is done
        :rtype: bool
        ..note: Since scapy doesn't parse the EAPOL key data for us we need
        to index the field by ourself. It is possible that the frame
        is malformed so catch the IndexError to prevent this.
        """

        # Catch the IndexError to prevent the malformed frame problem
        try:
            passphrase = self._data.args.presharedkey
            essid = self._data.target_ap_essid
            # constant for calculating PTK of 80211
            ap_mac = binascii.a2b_hex(''.join(self._data.target_ap_bssid.
                                              split(":")))
            # extract the APNonce from MSG-1
            ap_nonce = self._eapols[0].load[13:45]
            # address one of the MSG-1 is client's MAC address
            client_mac = binascii.a2b_hex(''.join(self._eapols[0].
                                                  addr1.split(":")))
            # extract the SNonce from MSG-2
            client_nonce = self._eapols[1].load[13:45]
            # constant for calculating PTK of 80211
            const_b = min(ap_mac, client_mac) + max(ap_mac, client_mac) +\
                min(ap_nonce, client_nonce) + max(ap_nonce, client_nonce)

            # calculate PMK first
            pmk = PBKDF2(passphrase, essid, 4096).read(32)
            ptk = self._prf512(pmk, constants.CONST_A, const_b)

            # get the key version to determine using HMAC_SHA1 or HMAC_MD5
            msg4 = self._eapols[3]
            key_version = 1 if ord(msg4.load[2]) & 7 else 0

            # start to construct the buffer for calculating the MIC
            msg4_data = format(msg4[dot11.EAPOL].version, '02x') +\
                format(msg4[dot11.EAPOL].type, '02x') +\
                format(msg4[dot11.EAPOL].len, '04x')
            msg4_data += binascii.b2a_hex(msg4.load)[:154]
            msg4_data += "00" * 18
            msg4_data = binascii.a2b_hex(msg4_data)

            # compare the MIC calculated with the MIC from air
            if key_version:
                # use SHA1 Hash
                msg4_mic_cal = hmac.new(ptk[0:16],
                                        msg4_data,
                                        hashlib.sha1).hexdigest()[:32]
            else:
                # use MD5 Hash
                msg4_mic_cal = hmac.new(ptk[0:16], msg4_data).hexdigest()[:32]

            msg4_mic_cmp = binascii.b2a_hex(msg4.load[-18:-2])

            return bool(msg4_mic_cmp == msg4_mic_cal)
        except IndexError:
            return False

    def is_valid_handshake_frame(self, packet):
        """
        Check if the Dot11 packet is a valid EAPOL KEY frame
        :param self: Fourway object
        :param packet: A scapy.layers.RadioTap object
        :type self: Fourway
        :type packet: scapy.layers.RadioTap
        :return True if this is an EAPOL KEY frame
        :rtype: bool
        """

        if packet.haslayer(dot11.Dot11) and packet.haslayer(dot11.EAPOL):
            if not self._is_retried_frame(packet) and\
                        packet[dot11.EAPOL].type == 3:
                return True
        return False

    def get_packet(self, packet):
        """
        Process the Dot11 packets and verifiy it is a valid
        eapol frames in a 80211 fourway handshake
        :param self: Fourway object
        :param packet: A scapy.layers.RadioTap object
        :type self: Fourway
        :type packet: scapy.layers.RadioTap
        :return: empty list
        :rtype: list
        ..note: In this extension we don't need to send the packets
        to the extension manager.
        """
        # append the capture of user first:
        if self._is_first and self._data.args.handshakecapture:
            pkts = dot11.rdpcap(self._data.args.handshakecapture)
            for pkt in pkts:
                if self.is_valid_handshake_frame(pkt):
                    self._eapols.append(pkt)
            self._is_first = False

        # check if verification is done
        if not self._is_done:
            # append to list if this is the key frame
            if self.is_valid_handshake_frame(packet):
                self._eapols.append(packet)

            # we may have collected the fourway handshake
            if len(self._eapols) > 3:
                ap_bssid = self._data.target_ap_bssid
                # from AP to STA
                msg1 = self._eapols[0]
                # from STA to AP
                msg2 = self._eapols[1]
                # from AP to STA
                msg3 = self._eapols[2]
                # from STA to AP
                msg4 = self._eapols[3]

                # if the following condition correct but the MIC is
                # not correct we can pop 2 EAPOLs in the list
                # AP -> STA and STA -> AP. We cannot pop 4 since the
                # next 2 frames may be the MSG1 and MSG2
                if msg1.addr2 == ap_bssid and\
                        msg3.addr2 == ap_bssid and\
                        msg2.addr1 == ap_bssid and\
                        msg4.addr1 == ap_bssid:
                    self._is_done = self._verify_creds()
                    self._is_captured = True
                    self._eapols.popleft()

                # remove the head of the eapol
                if not self._is_done:
                    self._eapols.popleft()
        return [["*"], []]

    def send_output(self):
        """
        Send the output the extension manager
        :param self: A Fourway object.
        :type self: Fourway
        :return: A list with the password checking information
        :rtype: list
        """

        ret_info = []
        pw_str = "Password: {0} for essid: {1}".format(
            self._data.args.presharedkey,
            self._data.target_ap_essid)

        if self._is_captured and not self._is_done:
            ret_info = ["WPA HANDSHAKE CAPTURED - " + pw_str +
                        " is not correct!"]
        elif self._is_captured and self._is_done:
            ret_info = ["WPA HANDSHAKE CAPTURED - " + pw_str +
                        " is correct!"]
        else:
            ret_info = ["WAIT for HANDSHAKE"]
        return ret_info

    def send_channels(self):
        """
        Send channels to subscribe
        :param self: A Fourway object.
        :type self: Fourway
        :return: empty list
        :rtype: list
        ..note: we don't need to send frames in this extension
        """

        return []
