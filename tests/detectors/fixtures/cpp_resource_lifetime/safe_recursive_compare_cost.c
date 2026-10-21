typedef struct Node Node;
struct Node {
    Node *child;
    Node *next;
};
#define NodeForEach(item, list) for ((item) = (list)->child; (item) != NULL; (item) = (item)->next)

static int compare_nodes(Node *left, Node *right)
{
    Node *left_item = NULL;
    Node *right_item = NULL;
    NodeForEach(left_item, left) {
        right_item = right_item ? right_item->next : right->child;
        if (right_item == NULL || !compare_nodes(left_item, right_item))
            return 0;
    }
    return right_item == NULL || right_item->next == NULL;
}
