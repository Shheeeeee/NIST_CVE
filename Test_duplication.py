from pptx import Presentation
import copy

def duplicate_slide(pres, index):
    try:
        template = pres.slides[index]
        blank_slide_layout = template.slide_layout
    except:
        blank_slide_layout = pres.slide_layouts[0]

    copied_slide = pres.slides.add_slide(blank_slide_layout)

    for shp in template.shapes:
        if not shp.has_text_frame or shp.text_frame.text != "":  # Vérifier si la forme contient du texte
            el = shp.element
            newel = copy.deepcopy(el)
            copied_slide.shapes._spTree.insert_element_before(newel, 'p:extLst')

    return copied_slide

# Le nom du template (modèle) et du fichier de sortie
template_path = "Bulletin_de_veille_TEMPLATE.pptx"
output_filename = "duplication.pptx"

# Ouvrir le modèle
presentation = Presentation(template_path)

# Copier la deuxième diapo (index 1 car l'index commence à 0)
second_slide = presentation.slides[1]
copied_slide = duplicate_slide(presentation, 1)

# Sauvegarder la nouvelle présentation
presentation.save(output_filename)

print(f"La diapo 2 a été copiée dans '{output_filename}' avec succès.")
