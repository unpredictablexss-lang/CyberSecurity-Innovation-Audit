struct Item { int id; };
#define READ_ITEM(value) \\
    ((value)->id)
int read(Item *item) { return READ_ITEM(item); }
