typedef struct Node Node;
struct Node { int key; Node *child; };
#define NodeForEach(item, list) for ((item) = (list)->child; (item) != NULL; (item) = (item)->child)

static Node *indexed_lookup(Node *list, int key)
{
    (void)list;
    (void)key;
    return NULL;
}

static int compare_indexed(Node *left, Node *right)
{
    Node *left_item = NULL;
    Node *right_item = NULL;
    NodeForEach(left_item, left) {
        Node *right_item = indexed_lookup(right, left_item->key);
        if (right_item == NULL || !compare_indexed(left_item, right_item))
            return 0;
    }
    NodeForEach(right_item, right) {
        Node *left_match = indexed_lookup(left, right_item->key);
        if (left_match == NULL || !compare_indexed(right_item, left_match))
            return 0;
    }
    return 1;
}
