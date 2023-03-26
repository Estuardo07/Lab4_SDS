import pefile
import os
import pandas as pd

source = './MALWR/'
malwr_data = []

for filename in os.listdir(source):
    if filename != '.DS_Store':  
        file_i = os.path.join(source, filename)
        pe = pefile.PE(file_i)

        # Leer PE header
        pe_header = {}
        pe_header_ImgBase = pe.OPTIONAL_HEADER.ImageBase
        pe_header_SecAlign = pe.OPTIONAL_HEADER.SectionAlignment


        # Leer PE sections
        #sections = []
        for section in pe.sections:
            #section_data = {}
            section_data_name = section.Name.decode('utf-8').rstrip('\x00')
            section_data_VirAdd = hex(section.VirtualAddress)
            #sections.append(section_data)

        # Leer APIs
        #imports = []
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            #import_data = {}
            import_data_dll = entry.dll.decode('utf-8').rstrip('\x00')
            import_data_funcs = []
            for function in entry.imports:
                import_data_funcs.append(function.name.decode('utf-8'))
            #imports.append(import_data)
	
        # Agregar la info a la lista
        malwr_data.append({
            'Filename': filename,
            'Header ImageBase': pe_header_ImgBase,
            'Header SectionAlignment': pe_header_SecAlign,
            'Section Name': section_data_name,
            'Section Virtual Address': section_data_VirAdd,
            'Imports dll': import_data_dll,
            'Imports funciones': import_data_funcs
        })

# Almacenar la info en un CSV

df = pd.DataFrame(malwr_data)
df.to_csv('dataset.csv')

# with open('dataset.csv', mode='w', newline='') as file:
#     writer = csv.writer(file)
#     writer.writerow(['Filename', 'PEHeader', 'Sections', 'Imports'])
#     for malware in malwr_data:
#         writer.writerow([malware['Filename'], malware['PEHeader'], malware['Sections'], malware['Imports']])
