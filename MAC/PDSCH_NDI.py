import os
import sys
import random

from collections import defaultdict

from mobile_insight.monitor import OfflineReplayer
from mobile_insight.analyzer.analyzer import *


class LteSampleAnalyzer(Analyzer):

    def __init__(self):
        Analyzer.__init__(self)

        # Add decoded data(log) and pass to _msg_callback
        self.add_source_callback(self.__msg_callback)

        self.init_timestamp = None
        ### init harq
        self._harq_to_array = defaultdict(list)
        self._harq_to_nack = defaultdict(list)
        self._scell_list = ["None"]

        ### init sampling related
        self._ct = 0
        self._next_sel = 0
        self._next_stop = 0
        self._select = False

        ### hyper-parameter for sampling
        # Must > 0
        self._min_sel = 2
        # Must > self._min_sel
        self._max_sel = 5
        self._min_skip = 0
        self._max_skip = 30

        ### init seed
        random.seed(42)

        ### init set sampling
        self.set_random_sampling()

    def set_source(self, source):
        """
        Set the trace source. Enable the cellular signaling messages

        :param source: the trace source (collector).
        """
        Analyzer.set_source(self, source)

        # source.enable_log_all()
        source.enable_log("LTE_PHY_PDSCH_Stat_Indication")


    def set_random_sampling(self):
        expected_sel = random.randint(self._min_sel, self._max_sel)
        expected_skip = random.randint(self._min_skip, self._max_skip)

        self._next_sel = self._ct + expected_skip
        self._next_stop = self._ct + expected_sel + expected_skip

        self.__clear_states()


    def __clear_states(self):
        self._harq_to_array = defaultdict(list)
        self._harq_to_nack = defaultdict(list)
        self._scell_list = ["None"]
    
    def selective_process(self):
        self._ct += 1
        if self._next_sel <= self._ct < self._next_stop:
            return True
        elif self._ct == self._next_stop:
            self.set_random_sampling()
            if self._ct == self._next_sel: return True
        
        return False
            

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
                scell_idx = 0
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

                        import json

                        # Temp
                        # rv = int(tb['RV'])
                        # if rv != 0: continue
                        # mcs = int(tb['MCS'])
                        # mt = str(tb['Modulation Type'])
                        rv = None
                        mcs = None
                        mt = None
                        #cell_id_str = record['Serving Cell Index']

                        ### hash to a new id
                        real_id = "HARQ:{} - ServingCell:{} - TBIdx:{} - TV:{} - MCS:{} - MT:{}".format(harq_id, \
                            self._scell_list[scell_idx], tb_idx, rv, mcs, mt)

                        self._harq_to_array[real_id].append(ndi)
                        self._harq_to_nack[real_id].append(nack)

                        # self.log_info( "LTE_PDSCH_Stat_Indication log item: " + json.dumps(log_item, indent=4, sort_keys=True, default=str))
                        # self.log_info( "LTE_PDSCH_Stat_Indication rec: " + str(log_item['Records']))
                        # self.log_info( "LTE_PDSCH_Stat_Indication tb: " + json.dumps(tb, indent=4, sort_keys=True, default=str))
                        # self.log_info( "LTE_PDSCH_Stat_Indication time: " + str(log_item['timestamp']))
                        # self.log_info( "LTE_PDSCH_Stat_Indication real_id: " + real_id)
                        # self.log_info( "LTE_PDSCH_Stat_Indication scell list: " + str(self._scell_list))
                        self.log_info( "Log#{} - LTE_PDSCH_Stat_Indication: ".format(self._ct) + 
                            "harq{}, SN_SFN:{}, NDI_List: {}, N/ACK_List: {}". \
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
        elif msg.type_id == "LTE_PHY_PDSCH_Stat_Indication" and self.selective_process():
            self.log_info("self._ct:{}. self._next_sel:{}. self._next_stop:{}.". \
                format(self._ct, self._next_sel, self._next_stop))
            self.callback_pdsch_stat(msg)


src = OfflineReplayer()
# Load offline logs
# src.set_input_path("./exp3VRFairStatic.mi2log")
src.set_input_path("./exp64GoodStatic.mi2log")
# src.set_input_path("./offline_log_examples/")

# Sample analyzer
lte_sample_analyzer = LteSampleAnalyzer() 
lte_sample_analyzer.set_source(src) #bind with the monitor

src.run()
