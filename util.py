import igraph as ig
import imageio
from pathlib import Path
import os
import os.path

def create_img_dir():
    if not os.path.isdir('./img'):
        os.mkdir('img')
        os.mkdir('img/attack_paths')


def make_gif_from_plots(filename: str = 'animation.gif') -> None:
    if not os.path.isdir('img/gif'):
        os.mkdir('img/gif')

    os.chdir('img/gif')

    image_list = list()
    images = list()
    for file in sorted(os.listdir(), key=os.path.getctime):
        if file.endswith('.png'):
            image_list.append(imageio.imread(file))
            images.append(file)

    imageio.mimwrite(filename, image_list, duration=0.5, fps=55)

    for img_file in images:
        os.remove(img_file)

    os.chdir('../../')


def save_graph(G: ig.Graph, layout_name='kk', filename: str = None):
    layout = G.layout(layout_name)

    if filename is None:
        filename = f'img/plot_{layout_name}.png'

    ig.plot(
        obj=G,
        target=filename,
        layout=layout,
        bbox=(1000, 1000),
        margin=(100, 100, 100, 100)
    )

def set_graph__display_attributes(G: ig.Graph) -> ig.Graph:
    G.vs['label'] = G.vs['name']
    G.vs['color'] = 'blue'
    G.es['width'] = 0.7
    G.vs['size'] = 35
    G.vs['label_dist'] = 2
    return G
