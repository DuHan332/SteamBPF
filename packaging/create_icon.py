"""Render the project's geometric B icon. Requires Pillow for regeneration only."""
from pathlib import Path
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
# An angular B monogram remains recognizable at small Windows icon sizes.
draw.polygon([(250,218),(625,218),(758,334),(758,428),(679,500),
              (790,593),(790,698),(658,814),(250,814)], fill='#64e1d2')
draw.polygon([(370,331),(583,331),(643,379),(583,430),(370,430)], fill='#13202a')
draw.polygon([(370,558),(611,558),(674,613),(674,648),(611,701),(370,701)], fill='#13202a')
# A detached coral corner adds a distinctive accent without a power motif.
draw.polygon([(691,190),(830,190),(830,329)], fill='#fa6559')
image = image.resize((512, 512), Image.Resampling.LANCZOS)
image.save(assets / 'steambpf.png')
image.save(assets / 'steambpf.ico', sizes=[(n, n) for n in (16, 20, 24, 32, 40, 48, 64, 128, 256)])
print('Created assets/steambpf.png and assets/steambpf.ico')
