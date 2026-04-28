# utils/doc_parsers.py
import os
import xlrd
import win32com.client
import pythoncom
import docx
import openpyxl
import pptx
import fitz # PyMuPDF

def parse_txt(file_path: str):
    """
    解析 TXT 文件。
    返回生成器，每次产出（行号，文本）
    """
    encodings = ['utf-8', 'gb18030', 'gbk', 'gb2312', 'utf-16']
    for enc in encodings:
        try:
            with open(file_path, 'r', encoding = enc)as f:
                for line_num, line in enumerate(f, start = 1):
                    text = line.strip()
                    if text:  # 只返回非空行
                        yield line_num, text
            return
        except UnicodeDecodeError:
            continue
    #所有编码尝试失败，抛出异常上层处理
    raise ValueError("无法识别文件编码或文件已损坏")

def parse_docx(file_path: str):
    """
    解析 Word(.docx) 文件
    由于 Word 非严格“行”换行，按 Paragraph 作为行号基准。
    """
    try:
        doc = docx.Document(file_path)
        for i, para in enumerate(doc.paragraphs, start=1):
            text = para.text.strip()
            if text:
                yield i, text
    except docx.opc.exceptions.PackageNotFoundError:
        # 捕获加密或损坏的 Word 文件异常
        raise ValueError("文档受保护(加密)或格式已损坏")
    
def parse_xlsx(file_path: str):
    """
    解析 Excel(.xlsx) 文件
    返回：（表名+行号，该行所有单元格拼接的文本）
    """
    try:
        # data_Only=True 只读取单元格的值，忽略公式
        wb = openpyxl.load_workbook(file_path, read_only=True, data_only=True)
        for sheet_name in wb.sheetnames:
            sheet = wb[sheet_name]
            for row_idx, row in enumerate(sheet.iter_rows(values_only=True), start=1):
                # 过滤空单元格，并将非空单元格的值转换为字符串后拼接
                row_texts = [str(cell) for cell in row if cell is not None and str(cell).strip()]
                if row_texts:
                    text = " | ".join(row_texts)  # 用 | 分隔单元格内容
                    yield f"表[{sheet_name}] - 第{row_idx}行", text
        wb.close()
    except Exception as e:
        raise ValueError(f"Excel读取失败或受保护: {str(e)}")

def parse_pptx(file_path: str):
    """
    解析 PowerPoint (.pptx) 文件。
    返回: (页码, 该页所有文本框拼接的文本)
    """
    try:
        prs = pptx.Presentation(file_path)
        for i, slide in enumerate(prs.slides, start=1):
            slide_text = []
            for shape in slide.shapes:
                if hasattr(shape, "text"):
                    slide_text.append(shape.text.strip())
            
            if slide_text:
                text = " ".join(slide_text).replace('\n', ' ')
                if text.strip():
                    yield f"第{i}页", text
    except Exception as e:
        raise ValueError(f"PPT读取失败或受保护: {e}")

def parse_pdf(file_path: str):
    """
    解析 PDF (.pdf) 文件。
    返回: (页码, 该页提取的所有文本)
    """
    try:
        doc = fitz.open(file_path)
        for i, page in enumerate(doc, start=1):
            text = page.get_text("text").strip()
            if text:
                text = text.replace('\n', ' ')
                yield f"第{i}页", text
        doc.close()
    except Exception as e:
        raise ValueError(f"PDF读取失败或受加密保护: {e}")
    
def parse_xls(file_path: str):
    """解析老版本 Excel (.xls) 文件"""
    try:
        # xlrd 专门处理 .xls
        wb = xlrd.open_workbook(file_path)
        for sheet in wb.sheets():
            for row_idx in range(sheet.nrows):
                row_values = sheet.row_values(row_idx)
                row_texts = [str(cell).strip() for cell in row_values if str(cell).strip()]
                if row_texts:
                    text = " | ".join(row_texts)
                    yield f"表[{sheet.name}] 第{row_idx+1}行", text
    except Exception as e:
        raise ValueError(f"老版本Excel读取失败: {e}")

def parse_doc(file_path: str):
    """使用 Windows COM 接口解析老版本 Word (.doc) 文件"""
    word_app = None
    doc = None
    try:
        pythoncom.CoInitialize()
        abs_path = os.path.abspath(file_path)
        
        word_app = win32com.client.DispatchEx("Word.Application")
        word_app.Visible = False
        word_app.DisplayAlerts = 0  # 0代表wdAlertsNone，彻底屏蔽任何警告弹窗
        
        # 【补丁】ConfirmConversions=False 明确拒绝任何格式转换弹窗
        # 如果喂给它的是伪装的PPT，它会立刻抛出异常而不是弹窗死等
        doc = word_app.Documents.Open(
            abs_path, 
            ConfirmConversions=False, 
            ReadOnly=True, 
            Visible=False
        )
        
        for i, para in enumerate(doc.Paragraphs, start=1):
            text = para.Range.Text.strip()
            if text:
                yield i, text
    except Exception as e:
        raise ValueError(f"老版本Word读取失败(格式不匹配、加密或损坏): {e}")
    finally:
        if doc:
            try:
                doc.Close(False)
            except:
                pass
        if word_app:
            try:
                word_app.Quit()
            except:
                pass
        pythoncom.CoUninitialize()

def parse_ppt(file_path: str):
    """使用 Windows COM 接口解析老版本 PowerPoint (.ppt) 文件"""
    ppt_app = None
    presentation = None
    try:
        pythoncom.CoInitialize()
        abs_path = os.path.abspath(file_path)
        
        ppt_app = win32com.client.DispatchEx("PowerPoint.Application")
        # 注意：PPT 的后台处理要求 WithWindow=False
        presentation = ppt_app.Presentations.Open(abs_path, ReadOnly=True, WithWindow=False)
        
        for i, slide in enumerate(presentation.Slides, start=1):
            slide_text = []
            for shape in slide.Shapes:
                if shape.HasTextFrame:
                    if shape.TextFrame.HasText:
                        slide_text.append(shape.TextFrame.TextRange.Text.strip())
            
            if slide_text:
                text = " ".join(slide_text).replace('\n', ' ').replace('\r', ' ')
                if text.strip():
                    yield f"第{i}页", text
    except Exception as e:
        raise ValueError(f"老版本PPT读取失败(可能加密或损坏): {e}")
    finally:
        if presentation:
            presentation.Close()
        if ppt_app:
            ppt_app.Quit()
        pythoncom.CoUninitialize()