###################################################################
#-----------------------------------------------------------------#
#-- Script que compara as secoes de 2 binarios PE              ---#
#-----------------------------------------------------------------#
###################################################################
import os, sys, pefile
from os.path import basename

###################################################################
#-----------------------------------------------------------------#
#-------------------- Funcoes AUXILIARES -------------------------#
#-----------------------------------------------------------------#
###################################################################

####################################################################################
# Funcao para receber uma lista como parâmetro e formata a saida
####################################################################################
def func_format_print(binary_file_section):
    if len(binary_file_section) > 0:
        section_print = "["
        for section in binary_file_section:
            section_print += section + ", "
        section_print = section_print[:-2] + "]"
    else:
        section_print = "[] * Nenhuma *"

    return section_print

####################################################################################
# Verifica as seções de dois arquivos binários passados como parâmatros
# Retorna uma array contendo as seções comuns e as seções apenas dos respectivos binários
####################################################################################
def func_get_pe_config(file_a, file_b):
    pe_config_files = dict()

    # Cria uma lista com os respectivos nomes
    list_name_sections_file_a = [name_section.Name.decode("UTF-8") for name_section in pefile.PE(file_a).sections]
    list_name_sections_file_b = [name_section.Name.decode("UTF-8") for name_section in pefile.PE(file_b).sections]
    # Cria no dicionario uma lista com a key "intersection" para incluir as section comuns entre os executaveis
    pe_config_files["intersection"] = []

    # Verifica as sessoes comuns entre os dois executaveis
    for section_file in list_name_sections_file_a:
        if section_file in list_name_sections_file_b:
            pe_config_files["intersection"].append(section_file)

    # Apos verificar as comuns, remove das listas para deixar apenas as unicas
    for section_file in pe_config_files["intersection"]:
        list_name_sections_file_a.remove(section_file)
        list_name_sections_file_b.remove(section_file)

    pe_config_files[basename(file_a)] = list_name_sections_file_a
    pe_config_files[basename(file_b)] = list_name_sections_file_b

    return pe_config_files

###################################################################
#-----------------------------------------------------------------#
#-----------------------------------------------------------------#
#----------------------- Funcao MAIN -----------------------------#
#-----------------------------------------------------------------#
#-----------------------------------------------------------------#
###################################################################

####################################################################################
if __name__ == '__main__':
    # Recebe como parâmetro um diretório com os arquivos binários
    if len(sys.argv) != 3:
        print(f"Erro: \nNumero de parametros incorreto \nFormato da "
              f"execução do script: python3 {basename(sys.argv[0])} "
              f"<caminho do binário A> <caminho do binário B>")
    else:
        # Verificar se os parametros passados sao arquivos (arquivo bin_1 = sys.argv[1] // arquivo bin_2 = sys.argv[2])
        if not os.path.isfile(sys.argv[1]) or not os.path.isfile(sys.argv[2]):
            print(f"Erro: \nParametros incorretos. Deve ser arquivos \nFormato da "
                  f"execução do script: python3 {basename(sys.argv[0])} "
                  f"<caminho do binário A> <caminho do binário B>")
        else:
            binary_file = func_get_pe_config(sys.argv[1], sys.argv[2])
            # Imprimi as secoes comuns entre os dois binarios
            print("Seções Comuns entre os Binarios: ", func_format_print(binary_file['intersection']))
            # Imprimi as secoes unicas do primeiro binario
            print(f"Seções Unicas do Binario \"{basename(sys.argv[1])}\": ", func_format_print(binary_file[basename(sys.argv[1])]))
            # Imprimi as secoes unicas do segundo binario
            print(f"Seções Unicas do Binario \"{basename(sys.argv[2])}\": ", func_format_print(binary_file[basename(sys.argv[2])]))
