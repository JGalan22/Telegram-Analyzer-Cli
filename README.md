# Telegram Analyzer CLI

_Herramienta para analizar grupos y canales de Telegram_


### Pre-requisitos 📋

_¿Qué cosas se necesitan para intarlar la herramienta?_

```
Python +3.6 

```
 Enlace para descargar [Python](https://www.python.org/downloads/)

### Instalación 🔧

_Pasos necesarios para instalar la herramienta._

_1 - Comprobar la versión de Python que tenemos instalada, ejecutamos UNA de las siguientes instrucciones._

```
python -V
python --version
```


_2 - Crear un directorio donde crearemos un entorno virtual_
_Crearemos el directorio en el path que queramos, por ejemplo:_

```
mkdir C:\tools\telegram-analyzer-cli #Ejecutar en la terminal de Windows en este caso
```
_Crear el entorno virtual en el directorio creado_
```
virutalenv telegram-analyzer-cli
```
Nota: En nuestro caso usamos virutalenv, para instalarlo:
```
pip install virtualenv
```
_3 - Descargar el proyecto en el directorio creado_

_4 - Activar el entorno virtual y posicionarnos en la carpeta de proyecto descargado._

_5 - Descargar todas las depenencias que están definidas en el archivo **requirements.txt** ejecutando:
```
pip install -r requirements.txt
```
Nota: Si aparece algún error revisar que estamos en el path correcto al mismo nivel que el archivo **requirements.txt**

_Si se ha seguido todo el proceso de instalación ya se puede usar la herramienta, pero antes configurar las credenciales.😁_

## Archivo de configuración ⚙️

_1 - Para poder usar la herramienta correctamente solo hay que crear una copia( o renombrarlo) de [Config-example.ini](https://gitlab.com/JesusGalan/telegram-analyzer-cli/-/blob/master/config-example.ini)_
```
# Renombrar o copiar config-example.ini por config.ini
```
_2 - Introducir las claves de las APIs y los datos de la base de datos tal y como indica el propio archivo_

_ Ahora sí, todo listo para usar la herramienta._😉

### Ejemplos de uso 🔩

_Ver que opciones podemos ejecutar_
```
python main.py --help
```


## Construido con 🛠️

_Este proyecto se ha creado con:_

* [Typer](https://github.com/tiangolo/typer) - Librería para el desarrollo de aplicaciones de consola
* [SQLAlchemy](https://github.com/sqlalchemy/sqlalchemy) - Librería para conexión con base de datos.






