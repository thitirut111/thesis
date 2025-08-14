# -*- coding: utf-8 -*-
from javax.swing import JPanel, JLabel, JTextField, JButton, JTextArea, JScrollPane
from java.awt import GridBagLayout, GridBagConstraints, Insets, Dimension
import subprocess

def create_panel():
    panel = JPanel()
    layout = GridBagLayout()
    panel.setLayout(layout)
    c = GridBagConstraints()

    # ช่องกรอก URL
    c.gridx = 0
    c.gridy = 0
    c.anchor = c.WEST
    c.insets = Insets(10, 10, 5, 5)
    panel.add(JLabel("Target URL:"), c)

    url_field = JTextField(30)
    c.gridx = 1
    c.weightx = 1.0
    c.fill = c.HORIZONTAL
    c.gridwidth = 1
    panel.add(url_field, c)

    # ฟังก์ชัน callback ปุ่ม Scan
    def on_scan_click(event):
        target_url = url_field.getText().strip()
        if target_url:
            output_area.setText("Running rengine...\n")
            try:
                process = subprocess.Popen(
                    ["python3", "rengineExtension.py", target_url],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT
                )

                stdout, _ = process.communicate()
                output_area.append(stdout.decode("utf-8"))
            except Exception as e:
                output_area.append("Error: " + str(e))

    # ปุ่ม Scan ให้อยู่ข้างหลังช่อง URL
    button = JButton("Scan", actionPerformed=on_scan_click)
    button.setPreferredSize(Dimension(100, 25))
    c.gridx = 2  # อยู่คอลัมน์ถัดไป
    c.gridy = 0
    c.weightx = 0
    c.fill = GridBagConstraints.NONE
    c.insets = Insets(10, 5, 5, 10)
    panel.add(button, c)

    # พื้นที่แสดงผลลัพธ์
    output_area = JTextArea(15, 50)
    output_area.setEditable(False) 
    output_area.setFocusable(False)
    scroll = JScrollPane(output_area)
    c.gridx = 0
    c.gridy = 1
    c.gridwidth = 3  # ขยายกว้างให้พอดีกับ 3 คอลัมน์
    c.weighty = 1.0
    c.fill = c.BOTH
    c.insets = Insets(10, 10, 5, 10)
    panel.add(scroll, c)

    return panel
