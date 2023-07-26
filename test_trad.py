from googletrans import Translator

def traduire_en_francais(texte):
    translator = Translator()
    try:
        traduction = translator.translate(texte, src='en', dest='fr')
        return traduction.text
    except:
        return texte

# Exemple d'utilisation :
texte_a_traduire = "Unchanged"
texte_traduit = traduire_en_francais(texte_a_traduire)
print(texte_traduit)
