"""Render the project's power-symbol icon. Requires Pillow for regeneration only."""
from pathlib import Path
import math
from PIL import Image, ImageDraw

SIZE = 1024
assets = Path(__file__).resolve().parent.parent / 'assets'
assets.mkdir(exist_ok=True)
image = Image.new('RGBA', (SIZE, SIZE))
gradient = Image.new('RGBA', (SIZE, SIZE))
pixels = gradient.load()
for y in range(SIZE):
    for x in range(SIZE):
        t = (x + y) / (2 * SIZE)
        pixels[x, y] = (int(29 - 19*t), int(45 - 29*t), int(59 - 36*t), 255)
mask = Image.new('L', (SIZE, SIZE))
ImageDraw.Draw(mask).rounded_rectangle((32, 32, 992, 992), radius=222, fill=255)
image.paste(gradient, (0, 0), mask)
draw = ImageDraw.Draw(image)
draw.rounded_rectangle((37, 37, 987, 987), radius=219, outline='#3a5362', width=9)
draw.arc((169, 169, 855, 855), 26, 334, fill='#233d49', width=9)
# A wide cyan power ring and coral switch echo the console's existing palette.
box = (250, 250, 774, 774)
draw.arc(box, -48, 228, fill='#64e1d2', width=76)
radius = 262 - 38
for angle in (-48, 228):
    a = math.radians(angle)
    x, y = 512 + radius*math.cos(a), 512 + radius*math.sin(a)
    draw.ellipse((x-38, y-38, x+38, y+38), fill='#64e1d2')
draw.rounded_rectangle((474, 201, 550, 525), radius=38, fill='#fa6559')
draw.rounded_rectangle((490, 214, 506, 490), radius=8, fill='#ff9281')
image = image.resize((512, 512), Image.Resampling.LANCZOS)
image.save(assets / 'steambpf.png')
image.save(assets / 'steambpf.ico', sizes=[(n, n) for n in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
print('Created assets/steambpf.png and assets/steambpf.ico')
