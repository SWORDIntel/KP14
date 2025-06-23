from PIL import Image, ImageDraw, ExifTags

def generate_jpeg_images():
    """Generates diverse JPEG images for testing."""
    base_dir = "test_images_jpeg"
    os.makedirs(base_dir, exist_ok=True)
    print(f"Ensured directory {base_dir} exists.")

    # 1. JPEG High Quality Large (800x600, RGB, Q=95)
    img_hq = Image.new("RGB", (800, 600), color="lightblue")
    draw_hq = ImageDraw.Draw(img_hq)
    draw_hq.rectangle([150, 150, 650, 450], fill="coral")
    draw_hq.text((50, 50), "JPEG High Quality (95)", fill="black")

    # Basic EXIF data
    exif_dict = {}
    # Standard EXIF tags (using numerical IDs)
    exif_dict[0x0131] = "Pillow Test Script"  # Software
    exif_dict[0x9286] = "High quality JPEG test image" # UserComment (Needs to be encoded properly, often as ASCII or UNDEFINED with a charset prefix)
                                               # For simplicity, Pillow might handle basic string encoding.

    # Pillow's Exif.dump expects values to be ASCII bytes or specific types.
    # Let's ensure UserComment is ASCII or provide it in a way Pillow expects for UNDEFINED type.
    # A common practice for UserComment is "ASCII\0\0\0Comment" or "UNICODE\0Comment"
    # However, Pillow's Exif.dump might simplify this. Let's try with a simple string first.
    # If issues arise, this might need more specific encoding.
    # For UserComment (0x9286), the type is UNDEFINED. Pillow might handle string to bytes.
    # Let's try to make it ASCII compatible for broader compatibility first.
    exif_dict[0x9286] = "High quality JPEG test image".encode("ascii", "ignore")

    # Create an Exif object and then get bytes
    exif_obj = Image.Exif()
    for k, v in exif_dict.items():
        exif_obj[k] = v
    exif_bytes = exif_obj.tobytes()

    path_hq = os.path.join(base_dir, "jpeg_high_quality_large.jpg")
    img_hq.save(path_hq, "JPEG", quality=95, exif=exif_bytes)
    print(f"Created {path_hq}")

    # 2. JPEG Low Quality Small (200x200, RGB, Q=50)
    img_lq = Image.new("RGB", (200, 200), color="lightgreen")
    draw_lq = ImageDraw.Draw(img_lq)
    draw_lq.ellipse([30, 30, 170, 170], fill="purple")
    draw_lq.text((10,10), "JPEG Low Q (50)", fill="white")
    path_lq = os.path.join(base_dir, "jpeg_low_quality_small.jpg")
    img_lq.save(path_lq, "JPEG", quality=50)
    print(f"Created {path_lq}")

    # 3. JPEG Grayscale (300x300, L, Q=80)
    img_gray = Image.new("L", (300, 300), color=128) # Mid-gray
    draw_gray = ImageDraw.Draw(img_gray)
    for i in range(0, 300, 15):
        draw_gray.line([(0, i), (300, i)], fill=0 if (i//15) % 2 == 0 else 200)
    draw_gray.text((20,20), "JPEG Grayscale Q (80)", fill=0) # Black text
    path_gray = os.path.join(base_dir, "jpeg_grayscale.jpg")
    img_gray.save(path_gray, "JPEG", quality=80)
    print(f"Created {path_gray}")

    # 4. JPEG with more EXIF (and ICC profile if possible)
    img_exif = Image.new("RGB", (400, 300), color="gold")
    draw_exif = ImageDraw.Draw(img_exif)
    draw_exif.polygon([(200,10), (10,290), (390,290)], fill="darkblue")
    draw_exif.text((20,20), "JPEG with EXIF", fill="black")

    exif_dict_more = {}
    # Example tags from ExifTags (using numerical IDs)
    exif_dict_more[0x013B] = "Test Artist"            # Artist
    exif_dict_more[0x8298] = "Copyright (C) 2024"     # Copyright
    exif_dict_more[0x0132] = "2024:07:26 10:00:00"     # DateTime
    exif_dict_more[0x010E] = "Test image with more EXIF data" # ImageDescription
    # For UserComment in this dict too, if desired:
    # exif_dict_more[0x9286] = "Another comment".encode('ascii', 'ignore')

    exif_obj_more = Image.Exif()
    for k, v in exif_dict_more.items():
        exif_obj_more[k] = v
    exif_bytes_more = exif_obj_more.tobytes()

    # Pillow's default sRGB ICC profile.
    # In a real scenario, you might load one from a file or copy from another image.
    # For simplicity, we'll just try to save with a common one if available in Pillow's internals,
    # or skip if it's too complex to bundle one. Pillow handles this internally if icc_profile=None.
    # Forcing it might require the profile bytes. Let's rely on Pillow's default handling for now.
    icc_profile_data = img_exif.info.get('icc_profile') # Will likely be None for a new image

    path_exif = os.path.join(base_dir, "jpeg_with_exif.jpg")
    img_exif.save(path_exif, "JPEG", quality=90, exif=exif_bytes_more, icc_profile=icc_profile_data)
    print(f"Created {path_exif}")

if __name__ == "__main__":
    import os # Import os here for os.path.join and os.makedirs
    generate_jpeg_images()
