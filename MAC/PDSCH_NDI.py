import os
import sys

from collections import defaultdict

from mobile_insight.monitor import OfflineReplayer
from mobile_insight.analyzer.analyzer import *


class LteSampleAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        # Add decoded data(log) and pass to _msg_callback
        self.add_source_callback(self.__msg_callback)

        self.init_timestamp = None
        self.___ct = 0

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        source.enable_log_all()
        source.enable_log("LTE_PHY_PDSCH_Stat_Indication")

        ### init harq
        self._harq_to_array = defaultdict(list)
        self._harq_to_nack = defaultdict(list)
        self._scell_list = []

    def callback_pdcp_ul_data(self, msg):
        log_item = msg.data.decode()
        # self.log_info log_item
        subPkt = log_item['Subpackets'][0]
        listPDU = subPkt['PDCPUL CIPH DATA']

        for pduItem in listPDU:
            # print pduItem
            sn = int(pduItem['SN'])
            sys_fn = int(pduItem['Sys FN'])
            sub_fn = int(pduItem['Sub FN'])

            self.log_info( "LTE_PDCP_UL_Cipher_Data_PDU: " + 
                "SN: {}, Sys FN: {}, Sub FN: {}". \
                format(sn, sys_fn, sub_fn) )

    def callback_pdcp_dl_data(self, msg):
        log_item = msg.data.decode()
        # self.log_info log_item
        subPkt = log_item['Subpackets'][0]
        listPDU = subPkt['PDCPDL CIPH DATA']

        for pduItem in listPDU:
            # print pduItem
            sn = int(pduItem['SN'])
            sys_fn = int(pduItem['Sys FN'])
            sub_fn = int(pduItem['Sub FN'])

            self.log_info( "LTE_PDCP_DL_Cipher_Data_PDU: " + 
                "SN: {}, Sys FN: {}, Sub FN: {}". \
                format(sn, sys_fn, sub_fn) )

    def callback_rlc_ul_data(self, msg):
        log_item = msg.data.decode()
        # self.log_info log_item
        subPkt = log_item['Subpackets'][0]
        listPDU = subPkt['RLCUL PDUs']

        for pduItem in listPDU:
            if not pduItem['PDU TYPE'] == 'RLCUL DATA': 
                continue
            # print pduItem
            sn = int(pduItem['SN'])
            sys_fn = int(pduItem['sys_fn'])
            sub_fn = int(pduItem['sub_fn'])

            self.log_info( "LTE_RLC_UL_AM_All_PDU: " + 
                "SN: {}, Sys FN: {}, Sub FN: {}". \
                format(sn, sys_fn, sub_fn) )

    def callback_rlc_dl_data(self, msg):
        log_item = msg.data.decode()
        # self.log_info log_item
        subPkt = log_item['Subpackets'][0]
        listPDU = subPkt['RLCDL PDUs']

        for pduItem in listPDU:
            if not pduItem['PDU TYPE'] == 'RLCDL DATA': 
                continue
            # print pduItem
            sn = int(pduItem['SN'])
            sys_fn = int(pduItem['sys_fn'])
            sub_fn = int(pduItem['sub_fn'])

            self.log_info( "LTE_RLC_DL_AM_All_PDU: " + 
                "SN: {}, Sys FN: {}, Sub FN: {}". \
                format(sn, sys_fn, sub_fn) )

    def callback_pdsch_stat(self, msg):
        log_item = msg.data.decode()

        if 'Records' in log_item:
            for i in range(0, len(log_item['Records'])):
                record = log_item['Records'][i]
                # scell_idx = 0
                if 'Transport Blocks' in record:
                    if 'Serving Cell Index' in record:
                        # two_tb_flag = True
                        cell_id_str = record['Serving Cell Index']
                        if cell_id_str not in self._scell_list:
                            self._scell_list.append(cell_id_str)
                        ### Add 1 b/c it by defualt == 0
                        scell_idx = self._scell_list.index(cell_id_str) 

                        ### SN anad SFN timer
                        sn = int(record['Frame Num'])
                        sfn = int(record['Subframe Num'])
                        sn_sfn = "(SN{}, SFN{})".format(sn,sfn)
                    for tb in log_item['Records'][i]['Transport Blocks']:
                        # if not two_tb_flag:
                        harq_id = int(tb['HARQ ID'])
                        ndi = int(tb['NDI'])
                        nack = str(tb['ACK/NACK Decision'])
                        tb_idx = int(tb['TB Index'])

                        ### hash to a new id
                        real_id = "HARQ{} - ServingCell{} - TBIdx{}".format(harq_id, \
                            self._scell_list[scell_idx], tb_idx)

                        self._harq_to_array[real_id].append(ndi)
                        self._harq_to_nack[real_id].append(nack)

                        # self.log_info( "LTE_PDSCH_Stat_Indication log item: " + str(log_item))
                        # self.log_info( "LTE_PDSCH_Stat_Indication rec: " + str(log_item['Records']))
                        # self.log_info( "LTE_PDSCH_Stat_Indication tb: " + str(tb))
                        self.log_info( "LTE_PDSCH_Stat_Indication real_id: " + real_id)
                        # self.log_info( "LTE_PDSCH_Stat_Indication scell list: " + str(self._scell_list))
                        self.log_info( "LTE_PDSCH_Stat_Indication: " + 
                            "harq{}, SN_SFN:{}, NDI List: {}, NACK List: {}". \
                            format(harq_id, sn_sfn, self._harq_to_array[real_id], \
                            self._harq_to_nack[real_id]))


    def __msg_callback(self, msg):
        if msg.type_id == "LTE_RLC_UL_AM_All_PDU":
            pass
            # self.callback_rlc_ul_data(msg)
        elif msg.type_id == "LTE_RLC_DL_AM_All_PDU":
            pass
            # self.callback_rlc_dl_data(msg)
        elif msg.type_id == "LTE_PDCP_UL_Cipher_Data_PDU":
            pass
            # self.callback_pdcp_ul_data(msg)
        elif msg.type_id == "LTE_PDCP_DL_Cipher_Data_PDU":
            pass
            # self.callback_pdcp_dl_data(msg)
        elif msg.type_id == "LTE_PHY_PDSCH_Stat_Indication":
            self.callback_pdsch_stat(msg)
            self.___ct = self.___ct + 1
            if self.___ct == 5:
                exit(0)


src = OfflineReplayer()
# Load offline logs
src.set_input_path("./exp3VRFairStatic.mi2log")

# Sample analyzer
lte_sample_analyzer = LteSampleAnalyzer() 
lte_sample_analyzer.set_source(src) #bind with the monitor

src.run()
