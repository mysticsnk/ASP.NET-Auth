namespace Notes_App.Features.Notes;

public class NoteService
{
    private readonly object _sync = new();
    private readonly List<Note> _notes = [];
    private int _nextId = 1;

    public Note Create(int ownerId, NoteRequest request)
    {
        var title = ValidateTitle(request.Title);
        var content = request.Content ?? string.Empty;

        lock (_sync)
        {
            var now = DateTimeOffset.UtcNow;
            var note = new Note(_nextId++, ownerId, title, content, now, now);
            _notes.Add(note);
            return note;
        }
    }

    public Note? GetById(int id)
    {
        lock (_sync)
            return _notes.FirstOrDefault(note => note.Id == id);
    }

    public List<Note> GetByOwnerId(int ownerId)
    {
        lock (_sync)
            return _notes.Where(note => note.OwnerId == ownerId).OrderByDescending(note => note.CreatedAt).ToList();
    }

    public Note? Update(int id, int ownerId, NoteRequest request)
    {
        var title = ValidateTitle(request.Title);
        var content = request.Content ?? string.Empty;

        lock (_sync)
        {
            var note = _notes.FirstOrDefault(n => n.Id == id && n.OwnerId == ownerId);
            if (note is null)
                return null;

            note.Update(title, content);
            return note;
        }
    }

    public bool Delete(int id, int ownerId)
    {
        lock (_sync)
        {
            var note = _notes.FirstOrDefault(n => n.Id == id && n.OwnerId == ownerId);
            return note is not null && _notes.Remove(note);
        }
    }

    public List<Note> GetAll()
    {
        lock (_sync)
            return [.. _notes];
    }

    private static string ValidateTitle(string? title)
    {
        if (string.IsNullOrWhiteSpace(title))
            throw new ArgumentException("Title cannot be empty.", nameof(title));

        return title.Trim();
    }
}

public sealed record NoteRequest(string? Title, string? Content);
