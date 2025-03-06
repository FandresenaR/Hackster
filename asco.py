import requests
from bs4 import BeautifulSoup
import csv
import time
import re

# Headers to mimic a browser visit
headers = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
}

# Base URL
base_url = "https://asco25.myexpoonline.com/co/"

# Full list of companies (all 497)
companies = [
    "A Breath of Hope Lung Foundation", "A Cure In Sight", "AARDEX Group", "AbbVie", "ABC Global Alliance",
    "Accessia Health", "Accord BiolParma", "Acrotech Biopharma", "Adaptive Biotechnologies Corpoention", "Adium",
    "Advanced Clinical", "Advanced CTS Corp.", "Advarta", "Advocates for Universal DPDDPYD Testing", "Agenda Inc.",
    "Agilent Technologies", "Abial", "Akeso Inc.", "Alliance for Fertility Preservation", "Alloy Therapeutics",
    "Allucent", "Almac", "Alpha Clinical Development Lid", "ALX Oncology", "American Association for Cancer Research",
    "American Brain Tumor Association", "American Cancer Society", "American College of Physicians, Inc.",
    "American Lung Cancer Screening Initiative", "American Society of Hematology", "Amgen", "Amoy Diagnostics Co, Ltd.",
    "Amplity Health", "AplusA", "Aptitude Health", "Arcells", "Arcus Biosciences", "Arvinas, Inc.", "Ascendis Pharma Inc.",
    "Ascentage Pharma", "ASCO State Oncology Societies", "ASCOR", "ASCO-Sponsored Patient Advocacy",
    "Association for Value-Based Cancer Care", "Association of Cancer Care Centers", "Association of Cannabinoid Specialists",
    "Astellas Pharma US, Inc.", "AstraZeneca", "Avanoe Clinical Pty Lud", "Aventa Geroenics", "AVEO Oncology, an LG Chem company",
    "Axiom Healthcare Strategies", "Aya Locums", "Azurity Phamaceuticals", "Bayer", "BEACON Medicare Limited",
    "BeiGene", "Benefits Health System", "Best Buy Health", "BicycleTxLid", "Billings Clinic Physician Recrutment",
    "BillionToOne", "Binuytan Foundation", "Biocare Medical", "Biodesix, Inc.", "Bixfidelity", "Biotixamis Inc",
    "Biomakers Inc", "BioNTech", "BioTouch", "Blue Spark Technologies, Inc.", "Blueprint Medicines", "Bochringer Ingelheim",
    "BostonGene", "Bradford Hill", "Brand Institute, Inc.", "Brim Analytics", "Bristol Myers Squibb", "Burning Rock DX L.LC",
    "Caidya", "Cancer Active, Inc., aka Throwing Bones for a Cure, Inc.", "Cancer and Careers", "Cancer Support Community",
    "CANCER101", "CancerCare", "Cardinal Health", "Caris Life Sciences", "Catalyst Clinical Research - Catalyst Oncology",
    "Celcuity", "Cellular Technology Lid.", "Certara", "ChemoMocthpiece, L.LC", "Cholangiocarcinoma Foundation",
    "Chugai Pharmaceutical Co., Ltd.", "Cikline", "City of Hope Cancer Care and Research", "Clario", "Cleveland Clinic Cancer Institute",
    "Clinical Education Alliance (CEA)", "Clinical Matrix Review", "CLL Society", "Cloudbyz", "CMIC Group", "Cogent Biosciences",
    "Coherus Biosciences", "College of American Pathologists", "Colorectal Cancer Alliance", "Complicalth", "ConcertAI",
    "Connectlfealth", "Cooler Heads", "Corcept Therapeutics", "Corewell Health", "Corramodical, Inc.",
    "Creative Portal for Oncology Education and More (CPOEM)", "Creatv Bio division of Creatv MicroTech Inc",
    "CTI Clinical Trial & Consulting Services", "Curis Inc.", "Daiichi Sankyo", "DAVA Oncology", "Day One Biopharmaceuticals, Inc.",
    "Debbie's Dream Foundation: Curing Stomach Cancer", "Deciphera Phamacesticals", "Definitive Healthcare", "Delfi Disgnostics, Inc.",
    "Delphi Diagnostics Inc.", "Dendroon Pharmacesticals", "Diagnostic Support Services", "DOD Congressionally Directed Medical Research Programs (CDMRP)",
    "Dosimity", "DPM | Digital Precision Medicine", "Dr. Park", "Dr. Reddy's Laboratories, Inc.", "Desty Joy Foundation (LiveLung)",
    "Early Access Care", "East Hawaii Medical Group & Hilo Medical Center", "ECO - European Cancer Organisation", "Eikon Therapeutics",
    "Eisai Inc.", "Eleplus", "Elevar Therapeutics", "Eli Lilly and Company", "EMD Serono", "Enable Injections", "End Brain Cancer Initiative",
    "Epic", "Epic Experience", "ERGOMED", "EVERSANA", "Exact Sciences", "Exai Bio", "Exelixis, Inc.", "FDA - Center for Biologics and Evaluation",
    "FDA CDER/DDI", "Femex Phamsaceuticals", "Fight Colorectal Cancer (FighnCRC)", "Finalis Molecular Precision Inc.", "Firefighter Cancer Support Network",
    "Flagship Biosciences, Inc.", "Flatine Health", "Florida Cancer Specialists & Research Institute", "Fore Biotherapeutics", "Foresight Diagnostics",
    "Fortrea", "Fosan Pharma USA", "Foundation Medicine, Inc.", "Fred Hutchinson Cancer Center", "FYR", "GE HealthCare",
    "Genecast Biotechnology Co, Ltd.", "Genentech", "Genetron Health", "Genmab", "GenomeWeb LLC", "Genomic Testing Cooperative",
    "GenPath", "Genscy Group", "George Clinical", "Geron, Inc.", "Gilead and Kite Oncology", "Glennsark Pharmaceuticals",
    "Global Cancer Alliance", "Global Colon Cancer Association", "Global Resource for Advancing Cancer Education", "GO2 for Lung Cancer",
    "GoPath Diagnostics", "Gradiam Biocoevergence", "GSK", "Guardant Health", "Hamamatsu Corporation", "Hangzhou Tigenned Consulting Co. LTD",
    "Harvest Integrated Research Organization Corp.", "Hayes Locums", "Haymarket Oncology", "Healin", "Health Volunteers Overseas",
    "HealthTree Foundation", "HealthWell Foundation", "Hedera Ds", "Hebirn", "HNC Living Foundation", "Holzer Health System",
    "Hoosier Cancer Research Network", "Hope For Stomach Cancer", "Hospice and Pallintive Nurses Association", "Hospital Ismelita Albert Einstein",
    "HPV Cancers Alliance", "Hummingbird Diagnostics Cimb41", "HungerNdThirst Foundation", "ICON", "Ilumina", "Imagerx", "Imaging Endpoints",
    "Inseman Angels One-on-One Cancer Support", "Immune Oncology Research Institute", "ImmunityBio", "Immunocore", "Immunocure Inc.",
    "IMO Health", "Incyte", "Indian Cancer Congress", "Inhibex Biosciences, Inc.", "Inezo", "Institut Curie", "Intemxountain Health",
    "International Association for the Study of Lung Cancer", "Intemational Myeloma Society", "International Society of Liquid Biopsy (ISLB)",
    "Inviscescribe, Inc.", "INVIVYD", "IO Biotech", "Iovance Biotherapeutics", "Ipsen Biopharmaceuticals, Inc.", "IQVIA", "Iteos Therapeutics",
    "ITM USA", "Japanese Society of Medical Oncology", "Jazz Pharmaceuticals", "John Theurer Cancer Center - Hackensack University Medical Hospital",
    "Johnson & Johnson", "Kapadi (OnooBay Clinical)", "Karger Publishers", "Karyopharm Therapeutics Inc.", "Kesem", "Klein Hersh",
    "Kognitic, Inc.", "KoNECT (Korea National Enterprise for Clinical Trials)", "Korean Society of Medical Oncology (KSMO)", "Kura Oncology",
    "La Roche-Posay", "LabConnect", "Labcorp", "LABORATORIO ELEA PHOENIX SA.", "Laboestario Vanifarma & Blanver", "Lantheus",
    "LeCancer FrPubliclin", "Legend Biotech USA", "Lexington Medical Center", "Li Fraumeni Syadrome Association", "LIVESTRONG Foundation",
    "LocumTenens.com", "Lone Star Oncology", "Lung Cancer Research Foundation", "LUNGevity Foundation", "Lurit USA", "Maple Tree Cancer Alliance",
    "Marshfield Clinic Health System", "Mashup Media LLC", "Massive Bio", "McKesson", "MD Anderson Cancer Center", "Med Learning Group",
    "Medable", "Modian Technologies", "Medical University of South Carolina", "Medicus Healthcare Solutions", "Mediduta, a Dassault Systèmes company",
    "Medlive", "Medpace Inc.", "MEDSCAPE ONCOLOGY", "Melanoma Research Foundation", "Menarini Silicon Bicosyslems", "Merck & Co., Inc.",
    "MercyOne", "MERIT", "Merus N.V.", "Mesothelioma Applied Research Foundation", "MIB Agents Osteosarcoma Alliance",
    "Michigan Medicine Laboratories (MLabs)", "Milestone One", "Milknnium Medical", "MJH Life Sciences", "Moderna", "Modulight Corp.",
    "Moffitt Cancer Center", "MultiCare Health System", "Multirational Association of Supportive Care in Cancer", "Mural Oncology",
    "MUSE Microscopy, Inc.", "Myelodysplastic Syndromes (MDS) Foundation, Inc", "Myriad Genetic Laboratories, Inc.", "myTomonows",
    "Natena", "National Blood Clot Alliance", "National Brain Tumor Society", "National Cancer Institute", "National Comprehensive Cancer Network (NCCN)",
    "National Organization for Rare Disorders (NORD)", "NCODA", "NeoGenomics", "Nikgen Oncosystems", "NMDP", "Nocthwell Health",
    "Northwest Biotherapeutics, Inc.", "Northwestem Medicine Lurie Cancer Center", "Novartis", "Nonocure Inc.", "Nucleai", "Novation Bio",
    "Ohio State University Comprehensive Cancer Center-James Cancer Hospital & Solove Research Institute", "Onc.AI", "Oncentric",
    "Oncol Host", "OncoKB", "Oncolens", "Oncology Learning Network", "Oncology Nursing Society", "Oncoscope AI LLC", "One Cancer Place",
    "OneCell Diagnostics", "OneMedNet", "Oncology", "ONO Pharma", "Onviv", "Open Health", "OPIS", "Opeam", "OueBninBank", "Owkin",
    "Paige AI", "Palloos Healthcare CimbH1", "PAN Foundation", "Parome Bio", "Parabilis Modicines", "Paradigm", "Parexel", "PathAI",
    "Patient Empowerment Network", "Pacman USA Inc", "Pear Bio", "Penn Medicine", "Perceptive", "Personalis, Inc.", "Perthera",
    "Pfizer Oncology", "PharmaMar", "Phesi, Inc.", "PHSE USA Corp.", "Pi Health", "Pickles Group", "Pictor Labs Inc.",
    "Piedmont Healthcare", "Pierre Fabre", "Pillar Biosciences", "Pink Fund", "Portamedic", "Practicelink", "Precision for Medicine",
    "Predicine", "Prelude Therapeutics", "Premier Research", "Premier|PNC AI Applied Sciences", "Prestige Biophama Limited",
    "Primum Health", "Project PINK BLUE", "ProMab Biotechnologies, Inc.", "PSI CRO", "QPS, Inc.", "QuantHealth", "Quest Diagrostics",
    "Quibim", "Qure.ai", "Radicenics", "RadMD", "Rakuten Medical, Inc.", "Rare Cancer Research Foundation", "RayzeBio",
    "Regeneron Pharmacouticals", "Replimune", "Research To Practice", "ResearchDx", "Resilience", "Resonant Clinical Solutions - EPL. Archives",
    "Revolution Medicines", "Rigel Phamacouticals", "Roswell Park Comprehensive Cancer Center", "Ruesch Center for the Cure of GI Canoers/Georgetown U.",
    "Rush University Medical Center", "Rutgers Cancer Institute/RWJBamabas Health", "SAGA Diagnostics", "San Antonio Breast Cancer Symposium",
    "Sarve", "Saroona Fousdation of America", "SCRI", "Sermo", "Servier Pharmacouticals L.LC", "Shengsheng International Logistics PTE LTD",
    "Sisters Network, Inc.", "Sites and Insights", "Sobi, Inc. - Commercial", "Society for Immunotherapy of Cancer",
    "Society for Translational Oncology / HARMONY", "SOPHiA GENETICS", "Springer Nature", "SpringWorks Therapeutics",
    "Stemline, a Menarini Group Compeny", "Summit Theripeutics", "SuperNOVA Clinical Research, Inc.",
    "Support for People with Oral and Head and Neck Cancer (SPOHNC)", "Susan G. Komen", "Syapoe", "Syncromuse, Inc.",
    "Syndax Pharmacouticals", "Syneas Health", "Sysmex Inostics", "Tailo Oncology Commercial", "Taibo Oncology, Inc. - Medical Affairs",
    "Takeda", "TargetCancer Foundation", "Telix Pharmaceuticals", "Telo Genomics", "Tempus", "TerSera Therapeutics, LLC",
    "TFS HealthScience", "The ASCO Post", "The Chick Mission", "The Leukemia & Lymphoma Society", "The Oncology Institute of Hope & Innovation",
    "The University of Vermont Health Network", "Theradex", "Thermo Fisher Scientific", "ThyCa: Thyroid Cancer Survivors' Association, Inc.",
    "Tigerlily Foundation", "Tolmar Inc.", "Towoh Bioscience", "Total Health Conferencing", "Translational Drug Development (TD2)",
    "Triage Cancer", "Trial Library", "TRIO - Translational Research in Oncology", "Truvets", "TubulisGmbH", "Twist Out Cancer", "UBC",
    "UCI Health", "Udderly Smooth/Redex Industries Inc.", "University of Cincinnati Cancer Center", "University of Illinois Cancer Center",
    "University of Miami Health System Sylvester Comprehensive Cancer Center", "University of Tennessee Physician Executive MBA Program",
    "UroGen Pharma Inc.", "Vaniam Group", "Varian, A Siemens Healthineers Company/Siemens Healthineers", "VCU Massey Comprehensive Cancer Center",
    "Velsera", "Veracyte", "Versiti Clinical Trials", "VHA National Oncology Program", "Visual Science", "Vitallalk", "Vivalink, Inx.",
    "Youant", "VYSIONEER", "WCG", "Weatherby Healthcare", "WEP Clinical", "Winstip Cancer Institute of Emory University",
    "Wolters Kluwer", "Wonders & Worries", "Worldwide Clinical Trials", "Worth the Wait", "Wren Laboratories, LLC", "WuXi Clinical",
    "Xenoor", "Y-mAbs Therupeutics, Inc.", "Young Adult Survives United"
]

# Function to format company name for URL
def format_company_name(name):
    # Replace special characters, spaces with hyphens, and lowercase
    name = re.sub(r'[^\w\s-]', '', name.lower())  # Remove special chars except hyphen and space
    name = re.sub(r'\s+', '-', name)  # Replace spaces with hyphens
    return name

# Function to scrape the official company website
def scrape_company_website(company_name):
    formatted_name = format_company_name(company_name)
    url = base_url + formatted_name
    print(f"Trying URL: {url}")
    try:
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Find all <a> tags on the page
        links = soup.find_all('a', href=True)
        print(f"Found {len(links)} links on the page:")
        for i, link in enumerate(links, 1):
            href = link['href']
            text = link.get_text(strip=True)
            print(f"  {i}. href='{href}', text='{text}'")
        
        # Look for the official website
        company_key = format_company_name(company_name).replace('-', '')  # e.g., "abbvie"
        for link in links:
            href = link['href']
            text = link.get_text(strip=True).lower()
            if (href.startswith('http') and 
                'asco25.myexpoonline.com' not in href and 
                'myexpoonline' not in href and 
                'jspargo.com' not in href and 
                'mailto:' not in href and 
                not href.endswith('.pdf')):
                # Prioritize if company name is in the URL
                if company_key in href.lower():
                    print(f"Selected website (matches company name): {href}")
                    return href
                # Fallback to links with "website" or "visit" in text
                elif any(keyword in text for keyword in ['website', 'visit', 'home', 'official']):
                    print(f"Selected website (text clue): {href}")
                    return href
        # Last resort: any valid external link
        for link in links:
            href = link['href']
            if (href.startswith('http') and 
                'asco25.myexpoonline.com' not in href and 
                'myexpoonline' not in href and 
                'jspargo.com' not in href and 
                'mailto:' not in href and 
                not href.endswith('.pdf')):
                print(f"Selected website (fallback): {href}")
                return href
        print("No suitable website found.")
        return "unknown"
    except requests.RequestException as e:
        print(f"Error fetching {url}: {e}")
        return "unknown"

# Scrape data and store results (all 497 companies)
results = []
for i, company in enumerate(companies, 1):
    print(f"\nScraping {i}/{len(companies)}: {company}")
    website = scrape_company_website(company)
    results.append([company, website])
    time.sleep(1)  # Be polite to the server

# Write to CSV
with open('company_websites.csv', 'w', newline='', encoding='utf-8') as csvfile:
    writer = csv.writer(csvfile)
    writer.writerow(['Company Name', 'Website'])  # Header
    writer.writerows(results)

print("\nScraping complete. Results saved to 'company_websites.csv'.")