namespace Notes_App.Features.Notes;

public class Note
{
    public Note(int id, int ownerId, string title, string content, DateTimeOffset createdAt, DateTimeOffset updatedAt)
    {
        Id = id;
        OwnerId = ownerId;
        Title = title;
        Content = content;
        CreatedAt = createdAt;
        UpdatedAt = updatedAt;
    }

    public int Id { get; }
    public int OwnerId { get; }
    public string Title { get; private set; }
    public string Content { get; private set; }
    public DateTimeOffset CreatedAt { get; }
    public DateTimeOffset UpdatedAt { get; private set; }

    public void Update(string title, string content)
    {
        Title = title;
        Content = content;
        UpdatedAt = DateTimeOffset.UtcNow;
    }
}
