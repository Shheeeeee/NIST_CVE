from pptx import Presentation

# Chemin d'accès au modèle PowerPoint
template_path = "chemin/vers/le/modèle.pptx"

# Crée une nouvelle présentation en utilisant le modèle
presentation = Presentation(template_path)

# Modifier la présentation comme souhaité
# ...

# Enregistre la présentation modifiée dans un fichier
presentation.save("nouvelle_presentation.pptx")
