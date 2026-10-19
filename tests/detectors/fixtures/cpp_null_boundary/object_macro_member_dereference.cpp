struct Item { int id; };
#define READ_ITEM item->id
int read(Item *item) { return READ_ITEM; }
