###################################################################
#-----------------------------------------------------------------#
#-- Script que analisa as permissoes de secoes em arquivos EXE ---#
#-- Ira processar apenas as secoes que                         ---#
#--   tenham permissao de execucao                             ---#
#--   O script permite analisar um diretorio com arquivos ou   ---#
#--    arquivo unico                                           ---#
#-----------------------------------------------------------------#
###################################################################
import os, sys, pefile
from pathlib import Path
from os.path import basename

###################################################################
#-----------------------------------------------------------------#
#-------------------- Funcoes AUXILIARES -------------------------#
#-----------------------------------------------------------------#
###################################################################

####################################################################################
# Funcao para recupera os arquivos .EXE de um diretorio passado como parametro
####################################################################################
def func_exe_dir(name_of_dir, file_suffix_name="*.exe"):
    files = []
    for filename in Path(name_of_dir).glob(file_suffix_name):
        print(filename)
        files.append(filename)
    return files

####################################################################################
# Funcao para analisar as secoes dos arquivos
####################################################################################
def func_get_sections_executables(arg_input):
    sections_executables = dict()

    # Verifica se parametro é um diretório
    # se sim, chama funcao para listar arquivos EXE do diretorio
    if os.path.isdir(arg_input) is True:
        files_list = func_exe_dir(arg_input)
    # Verifica se parametro é um arquivo
    elif os.path.isfile(arg_input) is True:
        files_list = [arg_input]
    # Se nao for diretorio ou arquivo, retorna "Nenhum"
    else:
        return None

    # Loop para um dos arquivos encontrados e colocando a lista de arquivos em ordem alfabetica
    for file in sorted(files_list, key=lambda path: str(path).lower()):
        # Instância da biblioteca pefile
        pe = pefile.PE(file)

        # Procura as secoes dos arquivos executaveis
        for file_sections in pe.sections:
            # Verifica se a seção é executável conforme comentário da função
            if file_sections.IMAGE_SCN_MEM_EXECUTE is True:
                if basename(file) in sections_executables.keys():
                    sections_executables[basename(file)].append(str(file_sections.Name.decode('utf-8')))
                else:
                    sections_executables[basename(file)] = [str(file_sections.Name.decode('utf-8'))]

    return sections_executables

###################################################################
#-----------------------------------------------------------------#
#-----------------------------------------------------------------#
#----------------------- Funcao MAIN -----------------------------#
#-----------------------------------------------------------------#
#-----------------------------------------------------------------#
###################################################################

####################################################################################
if __name__ == '__main__':
    # Verificar se o numero de paramentros eh diferente de 2 (1 script e 1 diretorio/arquivo)
    if len(sys.argv) != 2:
        print(f"Erro: Informe o diretório ou caminho do arquivo binário. \nFormato da execução do "
              f"script: python3 {basename(sys.argv[0])} "
              f"<diretório com os binários ou o caminho de um binário específico>")
    else:
        # Salva paramentro do diretorio/arquivo na variavel arg_input
        arg_input = sys.argv[1]
        file_sections_executables = func_get_sections_executables(arg_input)
        # Funcao "func_get_sections_executables" verifica se eh diretorio ou arquivo. Se nao for, retorna None
        if file_sections_executables is None:
            print(f"Erro: \nDiretorio ou Arquivo EXE invalido. \nFormato da execução do "
                  f"script: python3 {basename(sys.argv[0])} "
                  f"<diretório com os binários ou o caminho de um binário específico>")
        else:
            # Caso diretorio informado esteja vazio, ira gerar o erro
            if len(file_sections_executables.keys()) == 0:
                print(f"Erro: Nenhum retorno obtido. \n"
                      f"Verifique se a pasta \"{arg_input}\" não está vazia")
            # Mostra o resultado na tela
            else:
                for bin_file in file_sections_executables.keys():
                    # Verifica se possui mais de 1 secao executavel
                    if len(file_sections_executables[bin_file]) > 1:
                        print("Binário: ",basename(bin_file)," - Seções executáveis: ",end="")
                    else:
                        print("Binário: ",basename(bin_file)," - Seção executável: ",end="")
                    # Formatacao da lista de secoes executaveis do arquivo. Ex:  [ section1, section2, ...]
                    section_list = "["
                    for section_name in file_sections_executables[bin_file]:
                        section_list += section_name+", "
                    section_list = section_list[:-2]+"]"
                    # imprimi a secao de executaveis do arquivo
                    print(f"{section_list}")


