from PIL import Image

# Create a 10x10 black square image
img = Image.new('RGB', (10, 10), color = 'black')
img.save('base_image.png', 'png')