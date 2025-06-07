from PIL import Image, ImageDraw

def generate_images():
    # 1. RGB Large (800x600)
    img_rgb = Image.new("RGB", (800, 600), color="blue")
    draw_rgb = ImageDraw.Draw(img_rgb)
    draw_rgb.rectangle([100, 100, 700, 500], fill="yellow")
    draw_rgb.text((50, 50), "RGB Large", fill="black")
    img_rgb.save("test_images/png_rgb_large.png", "PNG")
    print("Created test_images/png_rgb_large.png")

    # 2. RGBA Small (100x100)
    img_rgba = Image.new("RGBA", (100, 100), color=(255, 0, 0, 128)) # Semi-transparent red
    draw_rgba = ImageDraw.Draw(img_rgba)
    draw_rgba.ellipse([10, 10, 90, 90], fill=(0, 255, 0, 255)) # Opaque green
    draw_rgba.text((5,5), "RGBA Small", fill=(0,0,0,255))
    img_rgba.save("test_images/png_rgba_small.png", "PNG")
    print("Created test_images/png_rgba_small.png")

    # 3. Palette (Indexed Color) (200x200)
    # Create an RGB image first, then convert to palette
    img_p_rgb = Image.new("RGB", (200, 200), color="green")
    draw_p = ImageDraw.Draw(img_p_rgb)
    draw_p.polygon([(100,10), (10,190), (190,190)], fill="magenta")
    draw_p.text((10,10), "Palette", fill="white")
    img_palette = img_p_rgb.convert("P", palette=Image.ADAPTIVE, colors=16) # Reduce to 16 colors
    img_palette.save("test_images/png_palette.png", "PNG")
    print("Created test_images/png_palette.png")

    # 4. Grayscale (150x150)
    img_gray = Image.new("L", (150, 150), color="white") # L mode for grayscale
    draw_gray = ImageDraw.Draw(img_gray)
    for i in range(0, 150, 10):
        draw_gray.line([(0, i), (150, i)], fill="black" if (i//10) % 2 == 0 else "gray")
    draw_gray.text((10,10), "Grayscale", fill="black")
    img_gray.save("test_images/png_grayscale.png", "PNG")
    print("Created test_images/png_grayscale.png")

if __name__ == "__main__":
    generate_images()
