struct Item { int id; };
namespace A { Item *_Nullable Lookup(); }
int read() { Item *item = B::Lookup(); return item->id; }
