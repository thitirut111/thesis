# -*- coding: utf-8 -*-


from burp import IBurpExtender, ITab
from javax.swing import JPanel, JLabel
import uiExtension

class BurpExtender(IBurpExtender, ITab):

    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # ตั้งชื่อ Extension ใน Burp
        callbacks.setExtensionName("AutoPT")

	# ใช้งานฟังก์ชันจาก uiExtension.py
        self._panel = uiExtension.create_panel()

        # เพิ่มแท็บเข้า Burp
        callbacks.addSuiteTab(self)

        return

    # ชื่อแท็บ
    def getTabCaption(self):
        return "Thesis"

    # คืนค่าเนื้อหาของแท็บ (JPanel)
    def getUiComponent(self):
        return self._panel
