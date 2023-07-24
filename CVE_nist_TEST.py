import requests
import datetime
from urllib.parse import quote
import time    

from pptx import Presentation
from pptx.util import Pt
from pptx.dml.color import RGBColor
from pptx.util import Pt, Inches  # Import the Inches function





def do_task():
    # Obtenir la date de début (17 juillet 2023 à 17:58:08)
    start_datetime = datetime.datetime(2023, 7, 19, 14, 15, 0)

    # Obtenir la date actuelle comme date de fin (18 juillet 2023 à 17:58:08)
    end_datetime = datetime.datetime(2023, 7, 19, 14, 16, 0)

    # Formater les dates dans le format ISO-8061 étendu
    start_date = start_datetime.strftime('%Y-%m-%dT%H:%M:%S.000%z')
    end_date = end_datetime.strftime('%Y-%m-%dT%H:%M:%S.000%z')

    # Encoder les caractères spéciaux dans les dates
    encoded_start_date = quote(start_date)
    encoded_end_date = quote(end_date)

    # URL de l'API du NIST pour les CVE avec les dates de début et de fin spécifiées
    # url = f'https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={encoded_start_date}&lastModEndDate={encoded_end_date}'
    url = f'https://services.nvd.nist.gov/rest/json/cves/2.0/?pubStartDate={encoded_start_date}&pubEndDate={encoded_end_date}'

    # Nombre maximal de tentatives
    max_attempts = 5

    # Faire la requête GET à l'API avec gestion des erreurs
    for attempt in range(1, max_attempts + 1):
        print(f"Connexion à l'API en cours... Tentative {attempt}")
        response = requests.get(url)

        if response.status_code == 200:
            data = response.json()
            print("Connexion réussie !")
            break

        # Attendre quelques secondes avant la prochaine tentative
        time.sleep(3)
    else:
        print("Impossible de se connecter à l'API après plusieurs tentatives. Veuillez réessayer plus tard.")
        exit()
    # ...

    if len(data) != 0:
        cve_items = data['vulnerabilities']
        cve_list = []
        
        # Parcourir chaque CVE et extraire les informations
        for cve_item in cve_items:
            # Extract the severity (baseScore)
            cve_id = cve_item['cve']['id']

            severity = None
            for i in range(1, 100):
                key = f'cvssMetricV{i}'
                if key in cve_item['cve']['metrics']:
                    cve_metrics = cve_item['cve']['metrics'][key][0]

                    #################
                    # severity
                    #################
                    try:
                        severity = cve_metrics['baseScore']
                    except KeyError:
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                            severity = cve_metrics['cvssData']['baseScore']
                        except KeyError:
                            # Si 'attackVector' n'existe pas, définir attack_vector comme None
                            severity = None
                        continue

            # Print severity for debugging purposes
            if severity is None:
                print(f"Severity not found for CVE: {cve_item['cve']['id']}")


            # Skip processing the CVE if severity is less than 8
            if (severity is not None and severity < 8) or cve_item['cve']['vulnStatus'] == "Rejected" or cve_item['cve']['vulnStatus'] == "Modified":
                print(f"Skipping CVE {cve_id} due to low severity or rejected/modified status")
                continue

            cve_id = cve_item['cve']['id']
            vuln_status = cve_item['cve']['vulnStatus']

            # Initialize variables to store extracted information
            attack_vector = None
            vector_string = None
            descriptions = []
            
            
            # If vulnStatus is "Undergoing Analysis", et "severity" == None only extract and print descriptions
            if vuln_status == "Undergoing Analysis" and severity == None:
                if 'descriptions' in cve_item['cve']:
                    descriptions_data = cve_item['cve']['descriptions']
                    for description in descriptions_data:
                        descriptions.append(description['value'])

                print(f"CVE ID: {cve_id}")
                print(f"Vuln Status: {vuln_status}")
                print(f"Descriptions: {descriptions}")
                print()

                #################
                # il faut chercher des mots clefs dans la description tel que RCE, ...
                #################

            else:
                for i in range(1, 100): # Essayer différentes clés pour extraire le baseScore
                    key = f'cvssMetricV{i}'  # Construire la clé correspondante
                    if key in cve_item['cve']['metrics']:
                        cve_metrics = cve_item['cve']['metrics'][key][0]
                        
                        
                        #################
                        # vectorString
                        #################
                        try:
                            # Essayer d'accéder à 'vectorString' dans cve_item['cve']['metrics'][key][0]['cvssData']
                            vector_string = cve_metrics['cvssData']['vectorString']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                vector_string = cve_metrics['cvssData']['vectorString']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                vector_string = None

                        #################
                        # attackVector
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            attack_vector = cve_metrics['attackVector']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                attack_vector = cve_metrics['cvssData']['attackVector']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                attack_vector = None
                        
                        #################
                        # attack_complexity 
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            attack_complexity = cve_metrics['attackComplexity']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                attack_complexity = cve_metrics['cvssData']['attackComplexity']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                attack_complexity = None
                        
                        #################
                        # privileges_required  
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            privileges_required = cve_metrics['privilegesRequired']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                privileges_required = cve_metrics['cvssData']['privilegesRequired']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                privileges_required = None
                        
                        #################
                        # userInteraction  
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            user_interaction = cve_metrics['userInteraction']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                user_interaction = cve_metrics['cvssData']['userInteraction']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                user_interaction = None
                        
                        #################
                        # scope   
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            scope = cve_metrics['scope']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                scope = cve_metrics['cvssData']['scope']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                scope = None

                        #################
                        # confidentiality_impact   
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            confidentiality_impact = cve_metrics['confidentialityImpact']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                confidentiality_impact = cve_metrics['cvssData']['confidentialityImpact']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                confidentiality_impact = None

                        #################
                        # integrityImpact   
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            integrity_impact = cve_metrics['integrityImpact']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                integrity_impact = cve_metrics['cvssData']['integrityImpact']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                integrity_impact = None
                        
                        #################
                        # availability_impact    
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            availability_impact = cve_metrics['availabilityImpact']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                availability_impact = cve_metrics['cvssData']['availabilityImpact']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                availability_impact = None

                        #################
                        # baseSeverity    
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            base_severity = cve_metrics['baseSeverity']
                        except KeyError:
                            try:
                                # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]['cvssData']
                                base_severity = cve_metrics['cvssData']['baseSeverity']
                            except KeyError:
                                # Si 'attackVector' n'existe pas, définir attack_vector comme None
                                base_severity = None

                        #################
                        # source    
                        #################
                        try:
                            # Essayer d'accéder à 'attackVector' dans cve_item['cve']['metrics'][key][0]
                            source = cve_item['cve']['references'][0]['url']
                        except KeyError:
                            source = None

                        
                        published = cve_item['cve']['published']
                        lastModified = cve_item['cve']['lastModified']

                # Extract 'descriptions'
                if 'descriptions' in cve_item['cve']:
                    descriptions = cve_item['cve']['descriptions'][0]['value']

                # Store all extracted information in a dictionary
                cve_info = {
                'cve_id': cve_id,
                'published': published,
                'lastModified': lastModified,
                'vector_string': vector_string,
                'attack_vector': attack_vector,
                'attack_complexity': attack_complexity,
                'privileges_required': privileges_required,
                'user_interaction': user_interaction,
                'scope': scope,
                'confidentiality_impact': confidentiality_impact,
                'integrity_impact': integrity_impact,
                'availability_impact': availability_impact,
                'severity': severity,
                'base_severity': base_severity,
                'descriptions': descriptions,
                'source' : source
            }

                cve_list.append(cve_info)

        for cve_info in cve_list:
            print(f"CVE ID: {cve_info['cve_id']}")
            print(f"publiée : {cve_info['published']}  modifiée : {cve_info['lastModified']}")

            print(f"Vuln Status: {vuln_status}")
            print(f"Severity: {cve_info['severity']}")
            print(f"base_severity: {cve_info['base_severity']}")

            print(f"Vector String: {cve_info['vector_string']}")
            print(f"Attack Vector: {cve_info['attack_vector']}")
            print(f"attack_complexity: {cve_info['attack_complexity']}")
            print(f"privileges_required: {cve_info['privileges_required']}")
            print(f"user_interaction: {cve_info['user_interaction']}")
            print(f"scope: {cve_info['scope']}")
            print(f"confidentiality_impact: {cve_info['confidentiality_impact']}")
            print(f"integrity_impact: {cve_info['integrity_impact']}")
            print(f"availability_impact: {cve_info['availability_impact']}")

            print(f"Descriptions: {cve_info['descriptions']}")
            print(f"Source: {cve_info['source']}")
            print()


        #################
        # powerpoint    
        #################

        # Chemin d'accès au modèle PowerPoint
        template_path = "Bulletin_de_veille_TEMPLATE.pptx"

        # Crée une nouvelle présentation en utilisant le modèle

        presentation = Presentation(template_path)

        slide = presentation.slides[1]  # Supposons que le tableau est sur la première diapositive
        table = None

        for shape in slide.shapes:
            if shape.has_table:
                table = shape.table
                break

        if table is None:
            print("Aucun tableau trouvé dans la diapositive.")
            exit()

        ######################################################

        # Tableau des coordonnées de cellules (lignes et colonnes)
        cell_coords = [(2, 2), (3, 2), (4, 2), (5, 2), (2, 6), (3, 6), (4, 6), (5, 6), (7, 1), (10, 1)]  # Exemple de coordonnées de cellules (à adapter à votre cas)

        # Tableau des valeurs pour les cellules correspondantes
        cell_values = [cve_info['attack_vector'], cve_info['attack_complexity'], cve_info['privileges_required'], cve_info['user_interaction'], cve_info['scope'], cve_info['confidentiality_impact'], cve_info['integrity_impact'], cve_info['availability_impact'], cve_info['descriptions'], cve_info['source']]  

        # Get the number of rows and columns in the table
        num_rows = len(table.rows)
        num_cols = len(table.columns)

        print("Number of rows:", num_rows)
        print("Number of columns:", num_cols)

        # Check the cell_coords list
        for row, col in cell_coords:
            if row > num_rows or col > num_cols:
                print(f"Invalid cell coordinate: ({row}, {col})")

        # Boucle pour modifier les cellules et les valeurs
        for i in range(len(cell_coords)):
            row, col = cell_coords[i]
            cell_value = cell_values[i]

            # Modifier le texte dans la cellule de la ligne et colonne spécifiées
            cell = table.cell(row, col)
            text_frame = cell.text_frame
            paragraph = text_frame.paragraphs[0]
            run = paragraph.add_run()

            # Modifier la mise en forme du texte
            run.text = cell_value
            run.font.size = Pt(11)
            run.font.name = "Poppins"
            run.font.color.rgb = RGBColor(0, 0, 0)  # Noir

        ######################################################

        # Tableau des coordonnées de cellules (lignes et colonnes)
        cell_coords = [(0, 1), (2, 8) , (9, 8)]  # Exemple de coordonnées de cellules (à adapter à votre cas)

        # Tableau des valeurs pour les cellules correspondantes
        cell_values = [cve_info['vector_string'], f"{str(cve_info['severity'])}\n{cve_info['base_severity']}", cve_info['base_severity']]  

        # Boucle pour modifier les cellules et les valeurs
        for i in range(len(cell_coords)):
            row, col = cell_coords[i]
            cell_value = cell_values[i]

            # Modifier le texte dans la cellule de la ligne et colonne spécifiées
            cell = table.cell(row, col)
            text_frame = cell.text_frame
            paragraph = text_frame.paragraphs[0]
            run = paragraph.add_run()

            # Modifier la mise en forme du texte
            run.text = cell_value
            run.font.size = Pt(11)
            run.font.name = "Poppins"
            run.font.bold = True  # Pour mettre le texte en gras
            run.font.color.rgb = RGBColor(255, 255, 255)  # Pour mettre le texte en blanc (255, 255, 255 correspond au blanc en RGB)

        ######################################################


        # Enregistrer la présentation modifiée dans un fichier
        output_path = "nouvelle_presentation.pptx"
        presentation.save(output_path)



    else:
        print(f'Aucune CVE trouvée pour la plage de dates spécifiée.')
    

# Fonction principale (main)
def main():
    print("Le programme démarre.")
    
    # Appeler la fonction auxiliaire pour effectuer une tâche spécifique
    do_task()
    print("Le programme se termine.")


# Vérifier si le fichier est exécuté en tant que programme principal
if __name__ == "__main__":
    main()