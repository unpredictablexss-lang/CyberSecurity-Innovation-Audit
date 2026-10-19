struct Item {
    int id;
};

Item *AliasFromOtherFunction();

int unknown_cross_function_alias_shape() {
    Item *item = AliasFromOtherFunction();
    return item->id;
}
