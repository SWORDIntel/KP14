from PIL import Image

img = Image.new('L', (100, 100), color = 'gray')
img.save('test_images_jpeg/jpeg_grayscale.jpg', 'jpeg')