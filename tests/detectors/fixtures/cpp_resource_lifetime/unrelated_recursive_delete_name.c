typedef struct Node Node;
typedef struct Patch Patch;
struct Node { Node *child; Node *next; };
struct Patch { Node *value; Patch *next; };

/* The name is intentionally misleading: this only walks children. */
static void cJSON_Delete(Node *item)
{
    if (item != NULL && item->child != NULL)
        cJSON_Delete(item->child);
}

static Node *cJSON_Duplicate(Node *source, int recurse)
{
    return recurse ? clone_node(source) : NULL;
}

static void attach_node(Node *root, Node *value)
{
    root->child = value;
}

static int apply_patch(Node *root, Patch *patch)
{
    Node *value = cJSON_Duplicate(patch->value, 1);
    if (value == NULL)
        return 1;
    attach_node(root, value);
    if (invalid_patch(patch)) {
        cJSON_Delete(value);
        return 1;
    }
    return 0;
}

static int apply_all(Node *root, Patch *patches)
{
    Patch *current = patches->next;
    while (current != NULL) {
        apply_patch(root, current);
        current = current->next;
    }
    return 0;
}
