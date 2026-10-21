typedef struct Node Node;
struct Node {
    int key;
    Node *child;
    Node *next;
};
#define NodeForEach(item, list) for ((item) = (list)->child; (item) != NULL; (item) = (item)->next)

static Node *lookup(Node *list, int key)
{
    Node *item = NULL;
    NodeForEach(item, list) {
        if (item->key == key)
            return item;
    }
    return NULL;
}

static int compare_nodes(Node *left, Node *right)
{
    Node *left_item = NULL;
    Node *right_item = NULL;
    NodeForEach(left_item, left) {
        right_item = lookup(right, left_item->key);
        if (right_item == NULL || !compare_nodes(left_item, right_item))
            return 0;
    }
    NodeForEach(right_item, right) {
        left_item = lookup(left, right_item->key);
        if (left_item == NULL || !compare_nodes(right_item, left_item))
            return 0;
    }
    return 1;
}
