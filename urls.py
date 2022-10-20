# -*- encoding: utf-8 -*-
"""
Copyright (c) 2019 - present AppSeed.us
"""

from django.urls import path, re_path
from apps.home import views
# from django.conf.urls import url

urlpatterns = [

    # The home page
    # path('', views.index, name='home'),
    path('', views.chart_data, name='home'),
    path('models.html',views.models),
    path("ui-maps.html",views.network_discovery),
    # path('', views.home),
    # path('ui-tables.html',views.home),
    # path(r'home/$', views.home, name='home'),
    # path('download',views.models,name="download"),
    # path('discovery', views.network_discovery, name="network"),

    # Matches any html file
    re_path(r'^.*\.*', views.pages, name='pages'),

]
