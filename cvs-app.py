import matplotlib.pyplot as plt
import streamlit as st
import pandas as pd
import numpy as np


doc = 'cve.csv'


st.title("CVE List DataSet")


@st.cache
def load_data(nrows):
    data = pd.read_csv(doc, index_col=0, encoding='latin-1', nrows=nrows)
    return data


@st.cache
def load_data_byname(name):
    data = pd.read_csv(doc, index_col=0, encoding='latin-1')
    filtered_data_byname = data[data["cwe_name"].str.upper().str.contains(name)]
    return filtered_data_byname


@st.cache
def load_data_bysummary(word):
    data = pd.read_csv(doc, index_col=0, encoding='latin-1')
    filtered_data_bysummary = data[data["summary"].str.contains(word, na=False)]
    return filtered_data_bysummary


@st.cache
def load_data_byscore(score):
    data = pd.read_csv(doc, index_col=0, encoding='latin-1')
    filtered_data_byscore = data[data["cvss"].astype(
        str).str.upper().str.contains(score)]
    return filtered_data_byscore


############ Almacenar Información#############################
data = load_data(500)
save_data = pd.read_csv(doc, delimiter=',')
save_data = load_data(50)

# --- LOGO ---#
st.sidebar.image('logo.png')
st.sidebar.image("cred.jpg")
st.sidebar.write("Adriel Eduardo Peregrina Soto - S20006770")
st.sidebar.markdown("##")

# --- SIDEBAR FILTERS ---#
if st.sidebar.checkbox("Desplegar todos los CVEs guardados"):
    st.write(data)

buscadorTitulo = st.sidebar.write("Buscar CVE especifico: ")
buscador = st.sidebar.text_input("Nombre")
botonTitulo = st.sidebar.button("Buscar")

buscadorDes = st.sidebar.write("Buscar descripción especifica: ")
palabra = st.sidebar.text_input("Palabra")
botonPalabra = st.sidebar.button("Buscar descripción")

Genere = st.sidebar.selectbox("Selecciona un nombre",
                              options=data['cwe_name'].unique())
BotonGenere = st.sidebar.button("Buscar por palabra")

# Episode = st.sidebar.selectbox("Selecciona cantidad de capitulos",
#                             options=data['episodes'].unique())
CvssBus = st.sidebar.write("Buscar por CVSS: ")
cvss = st.sidebar.text_input("CVSS")
BotonCvss = st.sidebar.button("Buscar por CVSS")

##### Guardar datos de episodios para el histograma ####################
save_data_forHistrograma = pd.DataFrame(save_data)

save_data_forHistrograma_ep = save_data_forHistrograma['cvss'].astype(
    float)
save_data_forHistrograma_ep = np.array(
    save_data_forHistrograma_ep).astype(float)

limite_Histograma = save_data_forHistrograma_ep.max()
limite_Histograma = int(limite_Histograma)

if st.sidebar.checkbox('Mostrar histograma'):
    mostrar = np.histogram(save_data_forHistrograma_ep, bins=limite_Histograma,
                           range=(save_data_forHistrograma_ep.min(),
                                  save_data_forHistrograma_ep.max()),
                           weights=None,
                           density=False)[0]
    st.bar_chart(mostrar)

# Grafica de barras ##############3
save_data_for_Barras = pd.DataFrame(save_data)

save_data_for_Barras_cvss = save_data_for_Barras['cvss'].astype(
    float)
save_data_for_Barras_name = save_data_for_Barras['cwe_name'].astype(
    str)

save_data_for_Barras_rating = np.array(
    save_data_for_Barras_cvss)

save_data_for_Barras_name = np.array(
    save_data_for_Barras_name)

if st.sidebar.checkbox('Mostrar grafica de barras'):
    dataframe, axis = plt.subplots()
    axis.bar(save_data_for_Barras_name, save_data_for_Barras_cvss, color = 'blue')
    axis.set_xlabel('Nombre')
    axis.set_ylabel('CVSS')
    axis.set_title('Riesgo de CVEs')

    st.pyplot(dataframe)

##############
save_data_for_Scatter = pd.DataFrame(save_data)
rng = np.random.RandomState(0)

save_data_for_Barras_cvss = save_data_for_Barras['cvss'].astype(
    float)

save_data_for_Barras_name = save_data_for_Barras['cwe_name'].astype(
    str)

if st.sidebar.checkbox('Mostrar grafica de dispersión'):
    dataframe, axis = plt.subplots()
    axis.scatter(save_data_for_Barras_cvss,
                save_data_for_Barras_name,
                color='blue',
                alpha=0.4,
                cmap='viridis')

    st.pyplot(dataframe)


if botonTitulo:
    filterbyname = load_data_byname(buscador.upper())
    rows = filterbyname.shape[0]
    st.dataframe(filterbyname)

if botonPalabra:
    filterbysummary = load_data_bysummary(palabra.upper())
    rows = filterbysummary.shape[0]
    st.dataframe(filterbysummary)

if BotonGenere:
    filtered_data_bysummary = load_data_bysummary(Genere)
    rows = filtered_data_bysummary.shape[0]
    st.dataframe(filtered_data_bysummary)

if BotonCvss:
    filtered_data_bycvss = load_data_byscore(cvss.upper())
    rows = filtered_data_bycvss.shape[0]
    st.dataframe(filtered_data_bycvss)