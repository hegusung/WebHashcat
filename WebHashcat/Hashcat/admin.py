from django.contrib import admin

# Register your models here.
from .models import Hashfile, Session, Hash, Search

admin.site.register(Hashfile)
admin.site.register(Session)
admin.site.register(Hash)
admin.site.register(Search)
