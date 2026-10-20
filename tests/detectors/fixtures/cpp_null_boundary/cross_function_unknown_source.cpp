struct Item { int id; };
Item *Lookup();
int dereference(Item *item) { return item->id; }
int caller() { Item *item = Lookup(); if (!item) return 0; return dereference(item); }
