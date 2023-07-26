import requests
import datetime
from urllib.parse import quote

# Obtenir les dates de début et de fin
start_datetime = datetime.datetime(2023, 7, 1)
end_datetime = datetime.datetime(2023, 7, 2)

# Formater les dates dans le format ISO-8061 étendu
start_date = start_datetime.strftime('%Y-%m-%dT%H:%M:%S.000%z')
end_date = end_datetime.strftime('%Y-%m-%dT%H:%M:%S.000%z')

# Encoder les caractères spéciaux dans les dates
encoded_start_date = quote(start_date)
encoded_end_date = quote(end_date)

# URL de l'API du NIST pour les CVE avec les dates de début et de fin spécifiées
url = f'https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2019-1010218'

# Faire la requête GET à l'API
response = requests.get(url)
data = response.json()

# Vérifier si des données sont présentes dans la réponse
if len(data) != 0:
    cve_items = data['vulnerabilities'] # Récuperer toutes les vulns sur la periode
    cve_list = []

    # Parcourir chaque CVE et extraire l'identifiant CVE
    for cve_item in cve_items:
        cve_id = cve_item['cve']['id']
        cve_severity = cve_item['cve']['metrics']['cvssMetricV31'][0]['cvssData']['baseScore']
        print(cve_severity)
        print()
        cve_list.append(cve_id) # et le mettre dans une liste ()

    # Afficher les identifiants CVE
    print(f'CVE modifiées entre {start_date} et {end_date}:')
    for cve_id in cve_list:
        print(cve_id)

else:
    print(f'Aucune CVE trouvée pour la plage de dates spécifiée.')