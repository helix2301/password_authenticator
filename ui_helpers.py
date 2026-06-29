import os
from PIL import Image, ImageTk
from config import LOGO_FILE

def load_logo(width=100):
    if not os.path.exists(LOGO_FILE):
        return None

    try:
        image = Image.open(LOGO_FILE)
        image.thumbnail((width, width))
        return ImageTk.PhotoImage(image)
    except Exception:
        return None
