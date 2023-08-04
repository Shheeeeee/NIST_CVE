
#################################################################################
#                                 TRADUCTION
#################################################################################

# def traduire_en_francais(texte):
#     translator = Translator()
#     try:
#         traduction = translator.translate(texte, src='en', dest='fr')
#         return traduction.text
#     except:
#         return texte

# def traduire_donnees_en_francais(cve_list):
#     for cve_info in cve_list:
#         cve_info['base_severity'] = traduire_en_francais(str(cve_info['base_severity']))
#         cve_info['attack_vector'] = traduire_en_francais(str(cve_info['attack_vector']))
#         cve_info['attack_complexity'] = traduire_en_francais(str(cve_info['attack_complexity']))
#         cve_info['privileges_required'] = traduire_en_francais(str(cve_info['privileges_required']))
#         cve_info['user_interaction'] = traduire_en_francais(str(cve_info['user_interaction']))
#         cve_info['scope'] = traduire_en_francais(str(cve_info['scope']))
#         cve_info['confidentiality_impact'] = traduire_en_francais(str(cve_info['confidentiality_impact']))
#         cve_info['integrity_impact'] = traduire_en_francais(str(cve_info['integrity_impact']))
#         cve_info['availability_impact'] = traduire_en_francais(str(cve_info['availability_impact']))
#         cve_info['descriptions'] = traduire_en_francais(str(cve_info['descriptions']))

#     return cve_list



#################################################################################
#                              MISE EN FORME
#################################################################################

# def mettre_majuscule_initiale(chaine):
#     # Convertir la chaîne en minuscules
#     chaine_minuscules = chaine.lower()
#     # Mettre en majuscule la première lettre
#     chaine_majuscule_initiale = chaine_minuscules.capitalize()
#     return chaine_majuscule_initiale

# def mettre_majuscule_initiale_tout(cve_list):
    # for cve_info in cve_list:
        # cve_info['base_severity'] = mettre_majuscule_initiale(str(cve_info['base_severity']))
        # cve_info['attack_vector'] = mettre_majuscule_initiale(str(cve_info['attack_vector']))
        # cve_info['attack_complexity'] = mettre_majuscule_initiale(str(cve_info['attack_complexity']))
        # cve_info['privileges_required'] = mettre_majuscule_initiale(str(cve_info['privileges_required']))
        # cve_info['user_interaction'] = mettre_majuscule_initiale(str(cve_info['user_interaction']))
        # cve_info['scope'] = mettre_majuscule_initiale(str(cve_info['scope']))
        # cve_info['confidentiality_impact'] = mettre_majuscule_initiale(str(cve_info['confidentiality_impact']))
        # cve_info['integrity_impact'] = mettre_majuscule_initiale(str(cve_info['integrity_impact']))
        # cve_info['availability_impact'] = mettre_majuscule_initiale(str(cve_info['availability_impact']))
        # cve_info['descriptions'] = mettre_majuscule_initiale(str(cve_info['descriptions']))











# def scrape_website(cve_id): # Pour scrapper directement le site du NIST
#     url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
#     try:
#         response = requests.get(url)
#         response.raise_for_status()
#         soup = BeautifulSoup(response.text, 'html.parser')
#         target_div = soup.find('div', class_='col-lg-3 col-md-5 col-sm-12')
#         content = target_div.text.strip()

#         pattern = r"Source:\s+(.+)"
#         match = re.search(pattern, content)
#         source_info = match.group(1)

#         return  source_info
#     except requests.exceptions.RequestException as e:
#         print("Error:", e)
#         return None
#     except AttributeError:
#         print("Div not found or website structure changed.")
#         return None