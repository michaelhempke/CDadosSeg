###################################################################
#-----------------------------------------------------------------#
#--- Script que analisa as permissoes que os APK solicitam    ----#
#--- O script nao faz distincao de permissoes do android      ----#
#___   ou outras permissoes	                             ----#
#-----------------------------------------------------------------#
###################################################################
import os, sys
import xml.etree.ElementTree as XMLET
from pathlib import Path
from os.path import basename, isfile, join
from bs4 import BeautifulSoup 

###################################################################
#-----------------------------------------------------------------#
#-------------------- Funcoes AUXILIARES -------------------------#
#-----------------------------------------------------------------#
###################################################################

####################################################################################
# Função para coletar os nomes dos arquivos do AndroidManifest em um diretorio
# O diretorio em questao sera passado como parametro do scritp
####################################################################################
def func_xml_dir(name_of_dir, file_prefix_name="AndroidManifest*"):
    files = []
    for filename in Path(name_of_dir).rglob(file_prefix_name):
        files.append(filename)
    return files

####################################################################################
# Função para recupera o nome da APK informado pelo usuario. 
# Exemplo: 
#	Nome_arquivo_XML: AndroidManifest_NOMEAPK.xml
#	Nome_APK: NOMEAPK
# A função retorna o "NOMEAPK" ou "None" caso não tenha encontrado
####################################################################################
def func_apk_name(file_name):
    base_name = basename(file_name)
    if base_name.find("_") == -1 or base_name.find(".") == -1:
        return None

    tmp_sub = base_name[base_name.find("_")+1:]
    apk_name = tmp_sub[:tmp_sub.find(".")]

    return apk_name.replace(" ", "-")


####################################################################################
# Função para retornar as permissoes de cada apk citado em uma lista de apks
# Retorna um dicionário com "key= nome do APK" e "valor = lista de permissões"
####################################################################################
def func_permissions_by_apk(list_files):
    permissions_list = dict()
    # Recupera o nome do APK com a funcao "func_apk_name(file_name)"
    for file_name in list_files:
        # Faz o parse do XML
        parse = XMLET.parse(file_name)
        # Recupera a tag raiz do XLM
        root_tag = parse.getroot()
        # Recupera o nome do pacote dentro da tag raiz do XML
        apk_name = func_apk_name(file_name)
        if apk_name is None:
            apk_name = root_tag.attrib['package']
      

        #Abre o arquivo XML e faz a leitura dele
        with open(file_name, 'r') as fn: data = fn.read() 
        xml_file = BeautifulSoup(data, "xml")

        #Busca todas as linhas das tags "uses-permission"
        permissions_tags = xml_file.find_all('uses-permission')

        #Adiciona cada atributo da permissao ao dicionario
        for pt in permissions_tags:
            permission_values = pt.get('android:name').split(".")
            permission = permission_values[len(permission_values) - 1]
            if apk_name in permissions_list.keys():
                permissions_list[apk_name].append(permission)
            else:
                permissions_list[apk_name] = [permission]

    return permissions_list

####################################################################################
# Função para retornar as permissoes UNICAS de cada apk citado em uma lista de apks
####################################################################################
def func_distinct_permissions_by_apk(permissions_by_apk):
    distinct_permissions = dict()
    # Copia as chaves da lista de permissoes por apk passada no parametro
    for default_permission_key in permissions_by_apk:
        distinct_permissions[default_permission_key] = []

    # Verificador de permissoes unicas para da apk da lista
    for permission_key in permissions_by_apk.keys():
        # Recupera a lista de permissões de cada apk
        permission_list = permissions_by_apk[permission_key]
        # Procura nas outras listas de permissoes dos apks se existe alguma permissão semelhante
        for permission in permission_list:
            # Variavel de controle para verificar se ha permissoes em outra lista
            check = True
            # Verificacao final se a permissao eh unica
            for permission_key_other in permissions_by_apk.keys():
                # Estrutura de controle para evitar verificacao na sua propria lista
                if permission_key_other != permission_key:
                    # Se a permissao nao eh unica, encerra verificacao para os outros apks da lista
                    if permission in permissions_by_apk[permission_key_other]:
                        check = False
                        break
            # Se a variavel de controle terminou como verdadeira, entao a permissao eh unica para o APK
            if check:
                distinct_permissions[permission_key].append(permission)

    return distinct_permissions

####################################################################################
# Função para retornar as permissoes IGUAIS entre os apks da lista (Interseccao)
####################################################################################
def func_apks_intersection(permissions_by_apk, distinct_permissions):
    # Se a lista de permissoes unicas for nula, faz essa verificacao antes na funcao "func_distinct_permissions"
    # Essa lista de permissoes unicas sera utilizada posteriomente para evitar de verificar esse tipo de permissao
    # com as outras, jah que sao unicas
    if distinct_permissions is None:
        distinct_permissions = func_distinct_permissions(permissions_by_apk)

    # Lista com as permissões que tem intersecção e as que não tem
    intersection_permissions = []
    not_intersection_permissions = []
    # Adiciona as permissoes unicas na lista de não intersecções
    for distinct_permission_key in distinct_permissions.keys():
        # Recupera a lista de permissões unicas da chave
        distinct_permissions_list = distinct_permissions[distinct_permission_key]
        # Adiciona na lista de nao interseccao para nao verificar depois
        for distinct_permission in distinct_permissions_list:
            not_intersection_permissions.append(distinct_permission)

    # Estrutura que ira verificar as interseccoes
    for intersection_key in permissions_by_apk.keys():
        # Recupera a lista de permissões da chave
        permissions_list = permissions_by_apk[intersection_key]
        # Faz a intersecção com todas as outras listas
        for intersection in permissions_list:
            # Se a permissão já está na lista de interseção, ignora e continua para a proxima permissao
            if intersection in intersection_permissions:
                continue
            # Se a permissão já está na lista de não intersecções, ignora e continua para a proxima permissao
            if intersection in not_intersection_permissions:
                continue

            # Verifica se o item está em todas as demais listas
            # Caso não esteja em uma, já cancela o loop (break)
            check = True
            for intersection_key_other in permissions_by_apk.keys():
                # Para não pesquisar na lista atual
                if intersection_key_other != intersection_key:
                    # Verifica se o item em análise não está na lista analisada
                    # Se não estiver continua procurando nas demais listas
                    if intersection not in permissions_by_apk[intersection_key_other]:
                        check = False
                        # Adiciona na lista de não intersecções
                        not_intersection_permissions.append(intersection)
                        break

            # Se check positivo, indica que o item pesquisado está em todas as demais listas
            if check:
                # Adiciona na lista de intersecção
                intersection_permissions.append(intersection)

    return intersection_permissions

###################################################################
#-----------------------------------------------------------------#
#-----------------------------------------------------------------#
#----------------------- Funcao MAIN -----------------------------#
#-----------------------------------------------------------------#
#-----------------------------------------------------------------#
###################################################################

####################################################################################
if __name__ == '__main__':
# Se houver mais de 2 argumentos no comando, ira gerar o alerta de como utilizar o script
    if len(sys.argv) != 2:
        print(
	    f"Erro: Numero de argumentos invalido \nFormato da execução do script: python3 {basename(sys.argv[0])} "
	    f"diretório")
	    # Seleciona o segundo argumento e salva na variavel (diretorio)
    else:
        dir_arg2 = sys.argv[1]
        #Verifica se o segundo argumento eh um diretorio
        if not os.path.isdir(dir_arg2):
            print(
            f"Erro: \nInforme o diretório. \nFormato da execução do script: python3 {basename(sys.argv[0])} "
            f"diretório dos arquivos AndroidManifest.xml")
        else:
            list_files = func_xml_dir(dir_arg2)
            # Impressão de permissões por APK do diretorio informado no parametro do comando
            apks_permissions = func_permissions_by_apk(list_files)
            print("############################\n##   Permissões por APK   ##\n############################")
            for apk_name in sorted(apks_permissions.keys()):
                print("------------------------------\n", apk_name+": ", "\n------------------------------")
                print(sorted(apks_permissions[apk_name]),"\n")

            # Impressoes unicas por APK, ou seja, apenas esse APK tem essa permissao
            distinct_permissions = func_distinct_permissions_by_apk(apks_permissions)
            print("###################################\n##   Permissões UNICAS por APK   ##\n###################################")
            for apk_name in sorted(distinct_permissions.keys()):
                if not distinct_permissions[apk_name]:
                    print(apk_name+": Nenhuma", "\n")
                    print("\n------------------------------")
                else:
                    print(apk_name+": ", "\n")
                    print(sorted(distinct_permissions[apk_name]),"\n------------------------------")

            # Impressão de permissões comuns entre os apk analisados
            intersections_permissions = func_apks_intersection(apks_permissions, distinct_permissions)
            print("###################################\n##   Permissões COMUNS por APK   ##\n###################################")
            print(sorted(intersections_permissions))

