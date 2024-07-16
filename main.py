import sys
import pefile
import datetime
import hashlib
from PyQt5.QtWidgets import (
    QApplication,
    QWidget,
    QVBoxLayout,
    QTextEdit,
    QPushButton,
    QFileDialog,
    QHBoxLayout,
    QMessageBox,
)
from PyQt5.QtGui import QPainter


class FileAnalyzer(QWidget):
    def __init__(self):
        super().__init__()

        self.initUI()

    def initUI(self):
        self.setWindowTitle("File Analyzer")
        self.setGeometry(100, 100, 420, 300)

        self.layout = QVBoxLayout()

        self.text_edit = QTextEdit(self)
        self.text_edit.setReadOnly(True)

        self.button_layout = QHBoxLayout()
        self.select_button = QPushButton("Select File", self, clicked=self.select_file)
        self.save_button = QPushButton("Save to .txt", self, clicked=self.save_to_txt)
        self.copy_button = QPushButton(
            "Copy to Clipboard", self, clicked=self.copy_to_clipboard
        )
        self.save_button.setDisabled(True)
        self.copy_button.setDisabled(True)

        self.button_layout.addWidget(self.select_button)
        self.button_layout.addWidget(self.save_button)
        self.button_layout.addWidget(self.copy_button)

        self.layout.addLayout(self.button_layout)
        self.layout.addWidget(self.text_edit)

        self.setLayout(self.layout)
        self.file_path = None

        # Apply custom CSS styles for white and black appearance
        self.setStyleSheet(
            """
            QWidget {
                background-color: #FFFFFF;
                color: #000000;
            }
            QTextEdit {
                background-color: #FFFFFF;
                border: 1px solid #000000;
                border-radius: 5px;
                padding: 5px;
            }
            QPushButton {
                background-color: #000000;
                color: #FFFFFF;
                border: 1px solid #FFFFFF;
                border-radius: 15px;
                padding: 8px 16px;
                margin-right: 10px;
            }
            QPushButton:hover {
                background-color: #333333;
            }
        """
        )

    def paintEvent(self, event):
        # Enable anti-aliasing for widget rendering
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        super().paintEvent(event)

    def select_file(self):
        options = QFileDialog.Options()
        file_path, _ = QFileDialog.getOpenFileName(
            self, "Select a file", "", "All Files (*)", options=options
        )
        if file_path:
            self.file_path = file_path
            self.process_file(file_path)

    def process_file(self, file_path):
        try:
            build_time = get_exe_build_time(file_path)
            pe_data = print_pe_data(file_path)
            hashes = compute_hashes(file_path)

            result = f"File Path: {file_path}\n"
            result += f"Build Time(DPS String): {build_time}\n"
            result += f"PE Data(PcaSvc String): {pe_data}\n"
            result += "Hashes:\n"
            for key, value in hashes.items():
                result += f"{key}: {value}\n"

            self.text_edit.setPlainText(result)
            self.save_button.setDisabled(
                False
            )  # Enable the save button if there is output.
            self.copy_button.setDisabled(
                False
            )  # Enable the copy button if there is output.

        except Exception as e:
            self.text_edit.setPlainText(f"Error: {str(e)}")
            self.save_button.setDisabled(True)  # Disable the save button on error.
            self.copy_button.setDisabled(True)  # Disable the copy button on error.

    def save_to_txt(self):
        if self.text_edit.toPlainText():
            options = QFileDialog.Options()
            file_path, _ = QFileDialog.getSaveFileName(
                self, "Save as .txt", "", "Text Files (*.txt)", options=options
            )
            if file_path:
                with open(file_path, "w") as file:
                    file.write(self.text_edit.toPlainText())

    def copy_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.text_edit.toPlainText())
        QMessageBox.information(
            self, "Copy to Clipboard", "Text copied to clipboard.", QMessageBox.Ok
        )


def get_exe_build_time(file_path):
    try:
        pe = pefile.PE(file_path)
        timestamp = pe.FILE_HEADER.TimeDateStamp
        build_time = datetime.datetime.fromtimestamp(timestamp, datetime.timezone.utc)
        return build_time.strftime(
            "%Y/%m/%d:%H:%M:%S"
        )  # Format as "2022/01/31:15:25:30"
    except Exception as e:
        return f"Error: {str(e)}"


def compute_hashes(file_path):
    with open(file_path, "rb") as f:
        data = f.read()

    md5_hash = hashlib.md5(data).hexdigest()
    sha1_hash = hashlib.sha1(data).hexdigest()
    sha256_hash = hashlib.sha256(data).hexdigest()

    pe = pefile.PE(file_path)
    imphash = pe.get_imphash()

    return {
        "MD5": md5_hash,
        "SHA-1": sha1_hash,
        "SHA-256": sha256_hash,
        "Imphash": imphash,
    }


def print_pe_data(file_path):
    pe = pefile.PE(file_path)
    size_of_image = pe.OPTIONAL_HEADER.SizeOfImage
    hex_size_of_image = hex(size_of_image)
    formatted_output = f"{hex_size_of_image.upper()}"  # 0x150      0x38  SizeOfImage:                   0xHEX
    return formatted_output


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = FileAnalyzer()
    window.show()
    sys.exit(app.exec_())
