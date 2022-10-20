import csv

from django import template
from django.contrib import messages
from django.db.backends.ddl_references import Table
from django.shortcuts import render,redirect
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse, HttpResponseRedirect
from django.template import loader
from django.urls import reverse
import pandas as pd
from django.http import HttpResponse
import pickle
from subprocess import run
import os
from tensorflow import keras


import matplotlib.pyplot as plt
import numpy as np
import seaborn as sns
import pickle

from pandas import io
from sklearn.preprocessing import LabelEncoder, MinMaxScaler, StandardScaler
from sklearn.decomposition import PCA

from apps.home.Reconnoitre.Reconnoitre.reconnoitre import main,print_banner,util_checks,signal_handler
#from apps.home.Reconnoitre.Reconnoitre import reconnoitre
#import csv
#import sys
#sys.path.append('home/syeda/Downloads/django-black-dashboard/apps/home/Reconnoitre/Reconnoitre/')
#import reconnoitre.py
def chart_data(request):
    data = []
    normal=[]
    with open("graph_attack.csv") as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        
        for row in csv_reader:
            data.append(row)
        # print({'data': data})
        my_dashboard = dict(data)
    with open("normal_traffic.csv") as csvfile:
        csv_reader = csv.reader(csvfile, delimiter=',')
        csv_reader_no = csv.reader(csvfile, delimiter=',')
        for row in csv_reader_no:
            normal.append(row)
        normal_traffic=dict(normal)

    i1 = 0
    i2 = 0
    i3 = 0
    for key, values in my_dashboard.items():
            if values == "1":
                i1 += 1
            elif values == "2":
                i2 += 1
            elif values == "3":
                i3 += 1
    keys = ['1', '2', '3']
    values = []
    values.append(i1)
    values.append(i2)
    values.append(i3)
        # print(my_dashboard)
    keys1 = my_dashboard.keys()  # {'A121', 'A122', 'A124', 'A123'}
    values1 = my_dashboard.values()

    keys_no=normal_traffic.keys()
    values_no=normal_traffic.values()

    listkeys = []
    listvalues = []


    listkeys_no = []
    listvalues_no = []

    for x in keys1:
        listkeys.append(x)

    for y in values1:
        listvalues.append(y)
    for z in keys_no:
        listkeys_no.append(z)

    for r in values_no:
        listvalues_no.append(r)

        
    context = {
                    'listkeys': listkeys,
                     'listvalues': listvalues,
                     'listkeys1':keys,
                      'listvalues1':values,
                       'listkeys_no':listkeys_no,
                        'listvalues_no':listvalues_no
                 }

    return render(request, 'home/index.html', context)



@login_required(login_url="/login/")
def index(request):
    context = {'segment': 'index'}

    html_template = loader.get_template('home/index.html')
    return HttpResponse(html_template.render(context, request))


@login_required(login_url="/login/")
def pages(request):
    context = {}
    # All resource paths end in .html.
    # Pick out the html file name from the url. And load that template.
    try:

        load_template = request.path.split('/')[-1]

        if load_template == 'admin':
            return HttpResponseRedirect(reverse('admin:index'))
        context['segment'] = load_template

        html_template = loader.get_template('home/' + load_template)
        return HttpResponse(html_template.render(context, request))

    except template.TemplateDoesNotExist:

        html_template = loader.get_template('home/page-404.html')

        return HttpResponse(html_template.render(context, request))

    except:
        html_template = loader.get_template('home/page-500.html')
        return HttpResponse(html_template.render(context, request))

    
def models(request):
    test_data = pd.read_csv(
        '/home/syeda/Downloads/django-black-dashboard/apps/home/test-data (2).csv')
    # attack=test_data.loc[:,'attack']
    test_data.drop(test_data.columns[0], axis=1, inplace=True)

    tst_data = test_data.copy()

    prot_le = LabelEncoder()
    prot_labels = prot_le.fit_transform(test_data.protocol_type)
    prot_labels = pd.Series(prot_labels)
    test_data['protocol_type'] = prot_labels
    encoded_srv = prot_le.fit_transform(test_data.service)
    test_data['service'] = encoded_srv
    flag_labels = pd.Series(prot_le.fit_transform(test_data.flag))
    test_data['flag'] = flag_labels
    pca_x = test_data.copy()

    pca_x_norm = MinMaxScaler().fit_transform(pca_x)
    comps = 14
    comp_cols = ["component_" + str(i + 1) for i in range(comps)]
    pca2 = PCA(n_components=comps)
    res2 = pca2.fit_transform(pca_x_norm)
    pca2_dataset = pd.DataFrame(data=res2, columns=comp_cols)

    rf = pickle.load(open(
        '/home/syeda/Downloads/django-black-dashboard/apps/home/finalized_model.sav',
        'rb'))

    # testdata1 = test_data.to_numpy()
    y_pred = rf.predict(pca2_dataset)
    # pred = np.argmax(y_pred, axis=1)
    output = pd.DataFrame(y_pred)
    output.to_csv('NB.csv')
    df1 = pd.read_csv('NB.csv')
    df1.drop(df1.columns[[0]], axis=1, inplace=True)
    a = df1.to_numpy()
    lst_Dos = []
    lst_Probe = []
    lst_R2L = []
    lst_normal = []
    normal_pos=[]
    d = 0
    p = 0
    r = 0
    n = 0
    for i in a:
        # print(i)
        if (i == [0]):
            lst_normal.append(0)
            normal_pos.append(n)
        n += 1
    for i in a:
        # print(i)
        if (i == [1]):
            lst_Dos.append(d)
        # print(lst_Dos)
        d += 1
    for i in a:
        # print(i)
        if (i == [2]):
            lst_Probe.append(p)
            # print("probe=>", lst_Probe)
        p += 1
    for i in a:
        # print(i)
        if (i == [3]):
            lst_R2L.append(r)
            # print("probe=>", lst_Probe)
        r += 1

    dos_dataset = []
    probe_dataset = []
    r2l_dataset = []
    normal_dataset = []
    for j in lst_Dos:
        dos = pca2_dataset.iloc[j]

        dos_dataset.append(dos)
    dos_pd = pd.DataFrame(dos_dataset)
    dos_pd['position'] = dos_pd.index

    for b in lst_Probe:
        probe = pca2_dataset.iloc[b]
        probe_dataset.append(probe)
    probe_pd = pd.DataFrame(probe_dataset)
    probe_pd['position'] = probe_pd.index

    for c in lst_R2L:
        r2l = pca2_dataset.iloc[c]
        r2l_dataset.append(r2l)
    r2l_pd = pd.DataFrame(r2l_dataset)
    r2l_pd['position'] = r2l_pd.index



    # print("R2l_dataset",r2l_dataset)
    rf_dos = pickle.load(open(
        '/home/syeda/Downloads/django-black-dashboard/apps/home/finalized_model_dos.sav',
        'rb'))
        
    rf_probe = pickle.load(open(
        '/home/syeda/Downloads/django-black-dashboard/apps/home/finalized_model._probe.sav',
        'rb'))
    file_name = "/home/syeda/Downloads/django-black-dashboard/apps/home/xgb_r2l.pkl"
    rf_r2l = pickle.load(open(file_name, "rb"))

    if len(dos_dataset) != 0:
        dos_datase=dos_pd.drop(columns=['position'],axis=1)
        y_pred_dos = rf_dos.predict(dos_datase)
        second_level_dos=pd.DataFrame(y_pred_dos)

        if len(probe_dataset)!=0:
            y_pred_probe = rf_probe.predict(probe_dataset)
            global second_level_probe
            second_level_probe = pd.DataFrame(y_pred_probe)
            a = second_level_dos.append(second_level_probe)
            a.to_csv("second_level.csv")
            print(a)
        elif len(r2l_dataset)!=0:
            y_pred_r2l = rf_r2l.predict(r2l_dataset)
            second_level_r2l = pd.DataFrame(y_pred_r2l)

            m = second_level_probe.append(second_level_r2l)
            m.to_csv("second_level.csv")
            print(m)
        else:

            # second_level_dos = pd.DataFrame(y_pred_dos)
            second_level_dos.to_csv("second_level.csv")

    elif len(probe_dataset) != 0:
        

        y_pred_probe = rf_probe.predict(probe_dataset)
        # global second_level_probe
        second_level_probe = pd.DataFrame(y_pred_probe)
        if len(r2l_dataset)!=0:
            y_pred_r2l = rf_r2l.predict(r2l_dataset)
            second_level_r2l = pd.DataFrame(y_pred_r2l)
            # global a
            a = second_level_probe.append(second_level_r2l)
            a.to_csv("second_level.csv")
            print(a)




    elif len(r2l_dataset) != 0:

        y_pred_r2l = rf_r2l.predict(r2l_dataset)
        second_level_r2l = pd.DataFrame(y_pred_r2l)
        second_level_r2l.to_csv("second_level.csv")

    df = pd.read_csv("/home/syeda/Downloads/django-black-dashboard/second_level.csv")
    df.drop(df.columns[0], axis=1, inplace=True)
    second_le = df.to_numpy()
    attack = []
    attack_pos = []

    f = 0
    s = 0
    g = 0
    nor=0
    for att in second_le:
        if att==[1]:
            attack.append(1)
            attack_pos.append(f)
        f += 1

    for att in second_le:
        if att == [2]:
            attack.append(2)
            attack_pos.append(s)
        s += 1

    for att in second_le:
        if att == [3]:
            attack.append(3)
            attack_pos.append(g)
        g += 1
    for att in second_le:
        if att==[0]:
            lst_normal.append(0)
            normal_pos.append(nor)
        nor+=1
    attack_conn = []
    for k in attack_pos:
        thread = tst_data.iloc[k]
        # for k in attack_pos:
        #     thread=test_data.iloc(k)
        attack_conn.append(thread)
    attack_con_pd = pd.DataFrame(attack_conn)

    attack_con_pd['position'] = attack_con_pd.index
    ga = pd.DataFrame(attack, columns=["prediction"])
    gad = pd.DataFrame(attack)
    gap = pd.DataFrame(attack_pos, columns=['position'])
    gapd = pd.DataFrame(attack_pos)
    # gapc=pd.DataFrame(attack_conn,columns=[''])
    graph_attack = pd.concat([gap, ga], axis=1)
    nor_val=pd.DataFrame(lst_normal)
    nop = pd.DataFrame(normal_pos, columns=['position'])
    nopd=pd.DataFrame(normal_pos)
    attack_table = pd.merge(attack_con_pd, graph_attack, on="position")
    # graph_attack=pd.DataFrame(attack_pos,attack)
    graph_attack_d = pd.concat([gapd, gad], axis=1)
    graph_attack_d.to_csv("graph_attack.csv", index=False)
    normal_traffic_d = pd.concat([nopd, nor_val], axis=1)
    graph_attack_d.to_csv("graph_attack.csv", index=False)
    normal_traffic_d.to_csv("normal_traffic.csv", index=False)
    # attack_conn.to_csv()
    # attack_table= pd.merge(attack,graph_attack, on="position")

    # print("attack_table",attack_table)
    # attack_table=pd.concat([attack_con_pd,ga],axis=1)
    attack_table.to_csv("Attack_table.csv", index=False)

    # out_dos=pd.DataFrame(y_pred_dos)
    # output_dos = pd.DataFrame(y_pred_dos, columns=['prediction'])
    out_dos = pd.DataFrame(y_pred_dos, columns=['attack'])
    # final_dos

    final_attack = pd.DataFrame(attack_pos, columns=['position'])
    final_dos = pd.DataFrame(lst_Dos, columns=['position'])
    # ab=pd.concat([final_dos])
    traffic_flow = pd.concat([final_dos, out_dos], axis=1)
    traffic_flow.to_csv("traffic_flow.csv", index=False)

    table = pd.read_csv('Attack_table.csv')
    allData = []
    for i in range(table.shape[0]):
        temp = table.loc[i]
        allData.append(dict(temp))
    
    return render(request, "home/models.html", {'allData': allData})



def home(request):

    df = pd.read_csv('C:/Users/cash/Desktop/django-black-dashboard/posi.csv')
    allData = []
    for i in range(df.shape[0]):
        temp = df.loc[i]
        allData.append(dict(temp))
    print("hello jee")
    return render(request, "home/ui-tables.html", {'allData': allData})
    
    
def network_discovery(request):
     
     outputlist=[]
     os.system("reconnoitre -t 185.117.153.1-255 -o suip-neighbors --pingsweep")
     read_data= pd.read_csv(
        '/home/syeda/Downloads/django-black-dashboard/suip-neighbors/targets.txt')
     msg=[list(i) for i in zip(*read_data.values)]
     
     context={"msg":msg,
     "alert_flag":True}
       
     return render (request,"home/asset_invent.html",context)




